#include "buffer.h"

#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <ipaugenblick_api.h>

static const char hex_chars[] = "0123456789abcdef";

/**
 * init the buffer
 *
 */

static void dump_buffer(buffer *b)
{
#if 0
	int i;

	printf("used %d size %d segments %d\n",b->used,b->size,b->buffers_count);
	for(i = 0;i < b->buffers_count;i++) {
		char *p = (char *)b->bufs_and_desc[i].pdata;
		printf("%s",p);
	}
	printf("\n");
#endif
}

buffer* buffer_init(void) {
	buffer *b;

	b = malloc(sizeof(*b));
	force_assert(b);

	b->ptr = NULL;
	b->size = 0;
	b->used = 0;
	b->buffers_count = 0;
	b->bufs_and_desc = NULL;

	return b;
}

buffer *buffer_init_buffer(const buffer *src) {
	buffer *b = buffer_init();
	buffer_copy_buffer(b, src);
	return b;
}

buffer *buffer_init_string(const char *str) {
	buffer *b = buffer_init();
	buffer_copy_string(b, str);
	return b;
}

void buffer_free(buffer *b) {
	if (NULL == b) return;
	int i;
	for(i = 0; i < b->buffers_count; i++) {
		ipaugenblick_release_tx_buffer(b->bufs_and_desc[i].pdesc);
	}
	free(b->bufs_and_desc);
	b->bufs_and_desc = NULL;
	b->buffers_count = 0;
	free(b);
}

void buffer_reset(buffer *b) {
	if (NULL == b) return;

	/* limit don't reuse buffer larger than ... bytes */
#if 0 /* VADIM - FIXME */
	if (b->size > BUFFER_MAX_REUSE_SIZE) {
		free(b->ptr);
		b->ptr = NULL;
		b->size = 0;
	} else 
#endif
		if (b->size > 0) {
		b->ptr[0] = '\0';
	}

	b->used = 0;
}

char *buffer_get_byte_addr(const buffer *b, int idx)
{
	int buffer_idx = idx / 1448;
	int buffer_offset = idx%1448;

	force_assert(buffer_idx < b->buffers_count);
	return ((char *)b->bufs_and_desc[buffer_idx].pdata) + buffer_offset;
}

size_t buffer_get_contigous_space(int idx)
{
	size_t buffer_offset = idx%1448;
	return 1448 - buffer_offset;
}

void buffer_move(buffer *b, buffer *src) {
	buffer tmp;

	if (NULL == b) {
		buffer_reset(src);
		return;
	}
	buffer_reset(b);
	if (NULL == src) return;

	tmp = *src; *src = *b; *b = tmp;
}

#define BUFFER_PIECE_SIZE 64
static size_t buffer_align_size(size_t size) {
	size_t align = BUFFER_PIECE_SIZE - (size % BUFFER_PIECE_SIZE);
	/* overflow on unsinged size_t is defined to wrap around */
	if (size + align < size) return size;
	return size + align;
}
static void buffer_realloc(buffer *b, size_t size);
/* make sure buffer is at least "size" big. discard old data */
static void buffer_alloc(buffer *b, size_t size) {
	int number_of_buffers;
	force_assert(NULL != b);
	if (0 == size) size = 1;

	if (size <= b->size) return;

	if(b->ptr != NULL) {
		buffer_realloc(b, size);
		return;
	}

	b->used = 0;
	number_of_buffers = size / 1448 + ((size%1448) != 0);
	b->bufs_and_desc = calloc(number_of_buffers, sizeof(b->bufs_and_desc[0]));
	force_assert(ipaugenblick_get_buffers_bulk(size, 
						-1, 
						number_of_buffers, 
						b->bufs_and_desc) == 0);
	b->buffers_count = number_of_buffers;
	b->size = /*size*/b->buffers_count*1448;
	b->ptr = b->bufs_and_desc[0].pdata;
	force_assert(NULL != b->ptr);
}

/* make sure buffer is at least "size" big. keep old data */
static void buffer_realloc(buffer *b, size_t size) {
	int number_of_buffers;
	force_assert(NULL != b);

	if (0 == size) size = 1;

	if (size <= b->size) return;

	int delta = size - b->size;
	number_of_buffers = delta / 1448 + ((delta%1448) != 0);
	b->bufs_and_desc = realloc(b->bufs_and_desc, 
			((b->buffers_count + number_of_buffers) *sizeof(b->bufs_and_desc[0])));
	force_assert(ipaugenblick_get_buffers_bulk(
			size,
			-1, 
			number_of_buffers,
			&b->bufs_and_desc[b->buffers_count]) == 0);
	b->buffers_count += number_of_buffers;
	b->size = /*size*/b->buffers_count*1448;
	if (b->ptr == NULL)
		b->ptr = b->bufs_and_desc[0].pdata;
	force_assert(NULL != b->ptr);
}


char* buffer_string_prepare_copy(buffer *b, size_t size) {
	force_assert(NULL != b);
	force_assert(size + 1 > size);

	buffer_alloc(b, size + 1);
	b->used = 0;
	buffer_commit(b, 0);

	return b->ptr;
}

char* buffer_string_prepare_append(buffer *b, size_t size) {
	force_assert(NULL !=  b);

	if (buffer_string_is_empty(b)) {
		return buffer_string_prepare_copy(b, size);
	} else {
		size_t req_size = b->used + size;

		/* not empty, b->used already includes a terminating 0 */

		buffer_realloc(b, req_size);

		return buffer_get_byte_addr(b, b->used - 1);
	}
}

void buffer_string_set_length(buffer *b, size_t len) {
	force_assert(NULL != b);
	force_assert(len + 1 > len);

	buffer_realloc(b, len + 1);

	buffer_commit(b, len);
}

void buffer_commit(buffer *b, size_t size)
{
	force_assert(NULL != b);
	force_assert(b->size > 0);

	if (0 == b->used) {
		ipaugenblick_set_buffer_data_len(
					b->bufs_and_desc[0].pdesc,
					1);
		b->used = 1;
	}

	if (size > 0) {
		/* check for overflow: unsigned overflow is defined to wrap around */
		force_assert(b->used + size > b->used);
		force_assert(b->used + size <= b->size);
		int current_buffer_idx = b->used / 1448;
		size_t space = buffer_get_contigous_space(b->used - 1);
		b->used += size;
		if (space <= size)
			ipaugenblick_set_buffer_data_len(
					b->bufs_and_desc[current_buffer_idx].pdesc,
					1448);
		else {
			int current_length = 
				ipaugenblick_get_buffer_data_len(
					b->bufs_and_desc[current_buffer_idx].pdesc);
			ipaugenblick_set_buffer_data_len(
				b->bufs_and_desc[current_buffer_idx].pdesc,
				current_length + size);
		}
	}
	char *p = buffer_get_byte_addr(b, b->used - 1);
	*p = '\0';
}

int buffer_strlen(buffer *b)
{
	int i;
	int len = 0;
	for(i = 0; i < b->buffers_count;i++) {
		int len2 = ipaugenblick_get_buffer_data_len(b->bufs_and_desc[i].pdesc);
		len += len2;
		if (len2 < 1448)
			break;
	}
	return len;
}

void buffer_copy_string(buffer *b, const char *s) {
	buffer_copy_string_len(b, s, NULL != s ? strlen(s) : 0);
}

void buffer_copy_string_len(buffer *b, const char *s, size_t s_len) {
	force_assert(NULL != b);
	force_assert(NULL != s || s_len == 0);

	buffer_string_prepare_copy(b, s_len);
	size_t copied = 0;
	while(copied < s_len) {
		size_t space = buffer_get_contigous_space(copied);
		char *p = buffer_get_byte_addr(b, copied);
		memcpy(p, s + copied, ((s_len - copied) > space) ? space : (s_len - copied));
		copied += ((s_len - copied) > space) ? space : (s_len - copied);
	}

	buffer_commit(b, s_len);
	dump_buffer(b);
}

static void buffer_copy_string_len_with_offset(buffer *b, 
						int offset,
						const char *s, 
						size_t s_len) {
	force_assert(NULL != b);
	force_assert(NULL != s || s_len == 0);
//printf("%s %s\n",__func__,s);

	size_t copied = 0;
	while(copied < s_len) {
		size_t space = buffer_get_contigous_space(copied + offset);
		char *p = buffer_get_byte_addr(b, copied + offset);
		memcpy(p, s + copied, ((s_len - copied) > space) ? space : (s_len - copied));
		copied += ((s_len - copied) > space) ? space : (s_len - copied);
	}
	force_assert(copied == s_len);
	buffer_commit(b, s_len);
	dump_buffer(b);
}

void buffer_copy_buffer(buffer *b, const buffer *src) {
	if (NULL == src || 0 == src->used) {
		buffer_string_prepare_copy(b, 0);
		b->used = 0; /* keep special empty state for now */
	} else {
		size_t copied = 0;
		size_t tocopy = buffer_string_length(src);
		buffer_string_prepare_copy(b, tocopy);
		while(copied < tocopy) {
			size_t space = buffer_get_contigous_space(copied);
			char *p = buffer_get_byte_addr(src, copied);
			size_t tocopy2 = (tocopy - copied > space) ? space : (tocopy - copied);
			buffer_copy_string_len_with_offset(b, copied, p, tocopy2);
			copied += tocopy2;
		}
		force_assert(b->used == src->used);
	}
	dump_buffer(src);
	dump_buffer(b);
}

void buffer_append_string(buffer *b, const char *s) {
	buffer_append_string_len(b, s, NULL != s ? strlen(s) : 0);
}

/**
 * append a string to the end of the buffer
 *
 * the resulting buffer is terminated with a '\0'
 * s is treated as a un-terminated string (a \0 is handled a normal character)
 *
 * @param b a buffer
 * @param s the string
 * @param s_len size of the string (without the terminating \0)
 */

void buffer_append_string_len(buffer *b, const char *s, size_t s_len) {
	char *target_buf;

	force_assert(NULL != b);
	force_assert(NULL != s || s_len == 0);

	size_t copied = 0;
	while(copied < s_len) {
		target_buf = buffer_string_prepare_append(b, s_len - copied);
		size_t space = buffer_get_contigous_space(b->used - 1);
		int tocopy = ((s_len - copied) > space) ? space : s_len - copied;
		if (tocopy > strlen(s+copied))
			tocopy = strlen(s+copied);
		memcpy(target_buf,s + copied, tocopy);
		buffer_commit(b, tocopy);
		copied += tocopy;
	}
	if (b->used > 0) {
		char *p = buffer_get_byte_addr(b, b->used-1);
		*p = '\0';
	}
	dump_buffer(b);
}

void buffer_append_string_buffer(buffer *b, const buffer *src) {
	if (NULL == src) {
		buffer_append_string_len(b, NULL, 0);
	} else {
		int copied = 0;
		int tocopy = buffer_string_length(src);

		while(copied < tocopy) {
			char *p = buffer_get_byte_addr(src, copied);
			size_t tocopy2 = buffer_get_contigous_space(copied);
			if ((tocopy2 + copied) > src->used)
				tocopy2 = src->used - copied;
			if (tocopy2 > strlen(p))
				tocopy2 = strlen(p);
			buffer_append_string_len(b, p, tocopy2);
			copied += tocopy2;
		}
	}
	if (b->used > 0) {
		char *p = buffer_get_byte_addr(b, b->used-1);
		*p = '\0';
	}
	dump_buffer(b);
}

void buffer_append_uint_hex(buffer *b, uintmax_t value) {
	char *buf;
	int shift = 0;

	{
		uintmax_t copy = value;
		do {
			copy >>= 8;
			shift += 2; /* counting nibbles (4 bits) */
		} while (0 != copy);
	}
	buf = buffer_string_prepare_append(b, shift);
	size_t space = buffer_get_contigous_space(b->used - 1);
//	buffer_commit(b, shift); /* will fill below */

	shift <<= 2; /* count bits now */
	size_t copied = 0;
	while (shift > 0) {
		shift -= 4;
		if (copied == space) {
			buffer_commit(b, copied);
			buf = buffer_get_byte_addr(b, b->used - 1);
			space = buffer_get_contigous_space(b->used - 1);
			copied = 0;
		}
		*(buf++) = hex_chars[(value >> shift) & 0x0F];
		copied++;
	}
}

static char* utostr(char * const buf_end, uintmax_t val) {
	char *cur = buf_end;
	do {
		int mod = val % 10;
		val /= 10;
		/* prepend digit mod */
		*(--cur) = (char) ('0' + mod);
	} while (0 != val);
	return cur;
}

static char* itostr(char * const buf_end, intmax_t val) {
	char *cur = buf_end;
	if (val >= 0) return utostr(buf_end, (uintmax_t) val);

	/* can't take absolute value, as it isn't defined for INTMAX_MIN */
	do {
		int mod = val % 10;
		val /= 10;
		/* val * 10 + mod == orig val, -10 < mod < 10 */
		/* we want a negative mod */
		if (mod > 0) {
			mod -= 10;
			val += 1;
		}
		/* prepend digit abs(mod) */
		*(--cur) = (char) ('0' + (-mod));
	} while (0 != val);
	*(--cur) = '-';

	return cur;
}

void buffer_append_int(buffer *b, intmax_t val) {
	char buf[LI_ITOSTRING_LENGTH];
	char* const buf_end = buf + sizeof(buf);
	char *str;

	force_assert(NULL != b);

	str = itostr(buf_end, val);
	force_assert(buf_end > str && str >= buf);

	buffer_append_string_len(b, str, buf_end - str);
}

void buffer_copy_int(buffer *b, intmax_t val) {
	force_assert(NULL != b);

	b->used = 0;
	buffer_append_int(b, val);
}

void buffer_append_strftime(buffer *b, const char *format, const struct tm *tm) {
	size_t r;
	char* buf;
	force_assert(NULL != b);
	force_assert(NULL != tm);

	if (NULL == format || '\0' == format[0]) {
		/* empty format */
		buffer_string_prepare_append(b, 0);
		return;
	}
	buf = buffer_string_prepare_append(b, 255);
	size_t space = buffer_get_contigous_space(b->used - 1);
	r = strftime(buf, space, format, tm);

	/* 0 (in some apis buffer_string_space(b)) signals the string may have
	 * been too small; but the format could also just have lead to an empty
	 * string
	 */
	if (0 == r || r >= space) {
		/* give it a second try with a larger string */
		buffer_string_prepare_append(b, 4095);
		buf = buffer_get_byte_addr(b, (b->used - 1) + 255);
		space = buffer_get_contigous_space((b->used - 1) + 255);
		r = strftime(buf, space, format, tm);
	}

	if (r >= buffer_string_space(b)) r = 0;

	buffer_commit(b, r);
}


void li_itostrn(char *buf, size_t buf_len, intmax_t val) {
	char p_buf[LI_ITOSTRING_LENGTH];
	char* const p_buf_end = p_buf + sizeof(p_buf);
	char* str = p_buf_end - 1;
	*str = '\0';

	str = itostr(str, val);
	force_assert(p_buf_end > str && str >= p_buf);

	force_assert(buf_len >= (size_t) (p_buf_end - str));
	memcpy(buf, str, p_buf_end - str);
}

void li_itostr(char *buf, intmax_t val) {
	li_itostrn(buf, LI_ITOSTRING_LENGTH, val);
}

void li_utostrn(char *buf, size_t buf_len, uintmax_t val) {
	char p_buf[LI_ITOSTRING_LENGTH];
	char* const p_buf_end = p_buf + sizeof(p_buf);
	char* str = p_buf_end - 1;
	*str = '\0';

	str = utostr(str, val);
	force_assert(p_buf_end > str && str >= p_buf);

	force_assert(buf_len >= (size_t) (p_buf_end - str));
	memcpy(buf, str, p_buf_end - str);
}

void li_utostr(char *buf, uintmax_t val) {
	li_utostrn(buf, LI_ITOSTRING_LENGTH, val);
}

char int2hex(char c) {
	return hex_chars[(c & 0x0F)];
}

/* converts hex char (0-9, A-Z, a-z) to decimal.
 * returns 0xFF on invalid input.
 */
char hex2int(unsigned char hex) {
	unsigned char value = hex - '0';
	if (value > 9) {
		hex |= 0x20; /* to lower case */
		value = hex - 'a' + 10;
		if (value < 10) value = 0xff;
	}
	if (value > 15) value = 0xff;

	return value;
}

char * buffer_search_string_len(buffer *b, const char *needle, size_t len) {
	size_t i;
	char *p;
	force_assert(NULL != b);
	force_assert(0 != len && NULL != needle); /* empty needles not allowed */

	if (b->used < len) return NULL;
	size_t remaining = len;
	size_t tocompare = len > 1448 ? 1448 : len;
	for(i = 0, p = buffer_get_byte_addr(b, i); i < b->used - remaining;) {	
		
		if (0 == memcmp(p, needle, tocompare)) {
			remaining -= tocompare;
			if (remaining == 0)
				return buffer_get_byte_addr(b, i);
		} else {
			remaining = len;
		}
		if ((i%1448) == 0) {
			p = buffer_get_byte_addr(b, i);
			tocompare = remaining > 1448 ? 1448 : remaining;
		} else {
			i++;
			p++;
			tocompare--;
		}
	}

	return NULL;
}

int buffer_is_empty(const buffer *b) {
	return NULL == b || 0 == b->used;
}

int buffer_string_is_empty(const buffer *b) {
	return 0 == buffer_string_length(b);
}

/**
 * check if two buffer contain the same data
 *
 * HISTORY: this function was pretty much optimized, but didn't handled
 * alignment properly.
 */

int buffer_is_equal(const buffer *a, const buffer *b) {
	size_t compared = 0;
	force_assert(NULL != a && NULL != b);

	if (a->used != b->used) return 0;
	if (a->used == 0) return 1;
	
	while(compared < a->used) {
		size_t tocompare = ((a->used - compared) > 1448) ? a->used - compared : 1448;
		char *p1 = buffer_get_byte_addr(a, compared);
		char *p2 = buffer_get_byte_addr(b, compared);

		if (memcmp(p1, p2, tocompare))
			break;
		compared += tocompare;
	}

	return (compared == a->used);
}

int buffer_is_equal_string(const buffer *a, const char *s, size_t b_len) {
	size_t compared = 0;
	force_assert(NULL != a && NULL != s);
	force_assert(b_len + 1 > b_len);

	if (a->used != b_len + 1) return 0;
	while(compared < b_len) {
		size_t tocompare = ((a->used - compared) > 1448) ? a->used - compared : 1448;
		if (tocompare > (b_len - compared))
			tocompare = b_len - compared;
		char *p = buffer_get_byte_addr(a, compared);
		if (memcmp(p, s + compared, tocompare)) {
			break;
		}
		compared += tocompare;
		s += tocompare;
	}
	char *p = buffer_get_byte_addr(a, a->used - 1);
	if ('\0' != *p) return 0;
	return (compared == b_len);
}

/* buffer_is_equal_caseless_string(b, CONST_STR_LEN("value")) */
int buffer_is_equal_caseless_string(const buffer *a, const char *s, size_t b_len) {
	size_t compared = 0;
	force_assert(NULL != a);

	if (a->used != b_len + 1) return 0;
	force_assert('\0' == a->ptr[a->used - 1]);

	while(compared < a->used) {
		size_t tocompare = ((a->used - compared) > 1448) ? a->used - compared : 1448;
		char *p = buffer_get_byte_addr(a, compared);

		if (strncasecmp(p, s, tocompare))
			break;
		compared += tocompare;
		s += tocompare;
	}
	return (compared == a->used);
}

int buffer_caseless_compare(const char *a, size_t a_len, const char *b, size_t b_len) {
	size_t const len = (a_len < b_len) ? a_len : b_len;
	size_t i;

	for (i = 0; i < len; ++i) {
		unsigned char ca = a[i], cb = b[i];
		if (ca == cb) continue;

		/* always lowercase for transitive results */
		if (ca >= 'A' && ca <= 'Z') ca |= 32;
		if (cb >= 'A' && cb <= 'Z') cb |= 32;

		if (ca == cb) continue;
		return ca - cb;
	}
	if (a_len == b_len) return 0;
	return a_len < b_len ? -1 : 1;
}

int buffer_is_equal_right_len(const buffer *b1, const buffer *b2, size_t len) {
	/* no len -> equal */
	if (len == 0) return 1;

	/* len > 0, but empty buffers -> not equal */
	if (b1->used == 0 || b2->used == 0) return 0;

	/* buffers too small -> not equal */
	if (b1->used - 1 < len || b2->used - 1 < len) return 0;

	size_t compared = 0;
	while(compared < len) {
		char *p1 = buffer_get_byte_addr(b1, compared + (b1->used - 1));
		char *p2 = buffer_get_byte_addr(b2, compared + (b2->used - 1));
		size_t tocompare = buffer_get_contigous_space(compared + (b1->used - 1));
		if (tocompare > 
			buffer_get_contigous_space(compared + (b2->used - 1)))
			tocompare = buffer_get_contigous_space(compared + (b2->used - 1));

		if (memcmp(p1, p2, tocompare))
			break;
		compared += tocompare;
	}

	return (compared == len);
}

void li_tohex(char *buf, const char *s, size_t s_len) {
	size_t i;

	for (i = 0; i < s_len; i++) {
		buf[2*i] = hex_chars[(s[i] >> 4) & 0x0F];
		buf[2*i+1] = hex_chars[s[i] & 0x0F];
	}
	buf[2*s_len] = '\0';
}

void buffer_copy_string_hex(buffer *b, const char *in, size_t in_len) {
	/* overflow protection */
	force_assert(in_len * 2 > in_len);

	buffer_string_set_length(b, 2 * in_len);
	size_t processed = 0;
	while (processed < in_len) {
		char *p = buffer_get_byte_addr(b, processed);
		size_t toprocess = (in_len - processed) > 1448 ? 1448 : (in_len - processed);
		li_tohex(p, in, toprocess);
		in += toprocess;
		processed += toprocess;
	}	
}

/* everything except: ! ( ) * - . 0-9 A-Z _ a-z */
static const char encoded_chars_rel_uri_part[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  00 -  0F control chars */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  10 -  1F */
	1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1,  /*  20 -  2F space " # $ % & ' + , / */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,  /*  30 -  3F : ; < = > ? */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  40 -  4F @ */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,  /*  50 -  5F [ \ ] ^ */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  60 -  6F ` */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1,  /*  70 -  7F { | } ~ DEL */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  80 -  8F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  90 -  9F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  A0 -  AF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  B0 -  BF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  C0 -  CF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  D0 -  DF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  E0 -  EF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  F0 -  FF */
};

/* everything except: ! ( ) * - . / 0-9 A-Z _ a-z */
static const char encoded_chars_rel_uri[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  00 -  0F control chars */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  10 -  1F */
	1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0,  /*  20 -  2F space " # $ % & ' + , */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,  /*  30 -  3F : ; < = > ? */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  40 -  4F @ */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,  /*  50 -  5F [ \ ] ^ */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  60 -  6F ` */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1,  /*  70 -  7F { | } ~ DEL */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  80 -  8F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  90 -  9F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  A0 -  AF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  B0 -  BF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  C0 -  CF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  D0 -  DF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  E0 -  EF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  F0 -  FF */
};

static const char encoded_chars_html[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  00 -  0F control chars */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  10 -  1F */
	0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  20 -  2F & */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0,  /*  30 -  3F < > */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  40 -  4F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  50 -  5F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  60 -  6F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,  /*  70 -  7F DEL */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  80 -  8F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  90 -  9F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  A0 -  AF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  B0 -  BF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  C0 -  CF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  D0 -  DF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  E0 -  EF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  F0 -  FF */
};

static const char encoded_chars_minimal_xml[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  00 -  0F control chars */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  10 -  1F */
	0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  20 -  2F & */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0,  /*  30 -  3F < > */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  40 -  4F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  50 -  5F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  60 -  6F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,  /*  70 -  7F DEL */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  80 -  8F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  90 -  9F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  A0 -  AF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  B0 -  BF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  C0 -  CF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  D0 -  DF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  E0 -  EF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  F0 -  FF */
};

static const char encoded_chars_hex[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  00 -  0F control chars */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  10 -  1F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  20 -  2F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  30 -  3F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  40 -  4F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  50 -  5F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  60 -  6F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  70 -  7F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  80 -  8F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  90 -  9F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  A0 -  AF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  B0 -  BF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  C0 -  CF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  D0 -  DF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  E0 -  EF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  F0 -  FF */
};

static const char encoded_chars_http_header[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,  /*  00 -  0F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  10 -  1F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  20 -  2F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  30 -  3F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  40 -  4F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  50 -  5F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  60 -  6F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  70 -  7F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  80 -  8F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  90 -  9F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  A0 -  AF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  B0 -  BF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  C0 -  CF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  D0 -  DF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  E0 -  EF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  F0 -  FF */
};



void buffer_append_string_encoded(buffer *b, const char *s, size_t s_len, buffer_encoding_t encoding) {
	unsigned char *ds, *d;
	size_t d_len, ndx;
	const char *map = NULL;

	force_assert(NULL != b);
	force_assert(NULL != s || 0 == s_len);

	if (0 == s_len) return;

	switch(encoding) {
	case ENCODING_REL_URI:
		map = encoded_chars_rel_uri;
		break;
	case ENCODING_REL_URI_PART:
		map = encoded_chars_rel_uri_part;
		break;
	case ENCODING_HTML:
		map = encoded_chars_html;
		break;
	case ENCODING_MINIMAL_XML:
		map = encoded_chars_minimal_xml;
		break;
	case ENCODING_HEX:
		map = encoded_chars_hex;
		break;
	case ENCODING_HTTP_HEADER:
		map = encoded_chars_http_header;
		break;
	}

	force_assert(NULL != map);

	/* count to-be-encoded-characters */
	for (ds = (unsigned char *)s, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) {
		if (map[*ds]) {
			switch(encoding) {
			case ENCODING_REL_URI:
			case ENCODING_REL_URI_PART:
				d_len += 3;
				break;
			case ENCODING_HTML:
			case ENCODING_MINIMAL_XML:
				d_len += 6;
				break;
			case ENCODING_HTTP_HEADER:
			case ENCODING_HEX:
				d_len += 2;
				break;
			}
		} else {
			d_len++;
		}
	}

	d = (unsigned char*) buffer_string_prepare_append(b, d_len);

	for (ds = (unsigned char *)s, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) {
		if (map[*ds]) {
			switch(encoding) {
			case ENCODING_REL_URI:
			case ENCODING_REL_URI_PART:
				d = (unsigned char*)buffer_get_byte_addr(b, b->used - 1);
				if (buffer_get_contigous_space(b->used - 1) < 3) {
					buffer_commit(b,
					buffer_get_contigous_space(b->used - 1));
					d = (unsigned char*)buffer_get_byte_addr(b, b->used - 1);
				}
				d[0] = '%';
				d[1] = hex_chars[((*ds) >> 4) & 0x0F];
				d[2] = hex_chars[(*ds) & 0x0F];
				buffer_commit(b, 3);
				break;
			case ENCODING_HTML:
			case ENCODING_MINIMAL_XML:
				d = (unsigned char*)buffer_get_byte_addr(b, b->used - 1);
				if (buffer_get_contigous_space(b->used - 1) < 6) {
					buffer_commit(b, 
					buffer_get_contigous_space(b->used - 1));
					d = (unsigned char*)buffer_get_byte_addr(b, b->used - 1);
				}
				d[0] = '&';
				d[1] = '#';
				d[2] = 'x';
				d[3] = hex_chars[((*ds) >> 4) & 0x0F];
				d[4] = hex_chars[(*ds) & 0x0F];
				d[5] = ';';
				buffer_commit(b, 6);
				break;
			case ENCODING_HEX:
				d = (unsigned char*)buffer_get_byte_addr(b, b->used - 1);
				if (buffer_get_contigous_space(b->used - 1) < 2) {
					buffer_commit(b, 
					buffer_get_contigous_space(b->used - 1));
					d = (unsigned char*)buffer_get_byte_addr(b, b->used - 1);
				}
				d[0] = hex_chars[((*ds) >> 4) & 0x0F];
				d[1] = hex_chars[(*ds) & 0x0F];
				buffer_commit(b, 2);
				break;
			case ENCODING_HTTP_HEADER:
				if (buffer_get_contigous_space(b->used - 1) < 2) {
					buffer_commit(b, 
					buffer_get_contigous_space(b->used - 1));
					d = (unsigned char*)buffer_get_byte_addr(b, b->used - 1);
				}
				d[0] = *ds;
				d[1] = '\t';
				buffer_commit(b, 2);
				break;
			}
		} else {
			if (buffer_get_contigous_space(b->used - 1) < 1) {
				buffer_commit(b, 
				buffer_get_contigous_space(b->used - 1));
				d = (unsigned char*)buffer_get_byte_addr(b, b->used - 1);
			}
			d[d_len++] = *ds;
			buffer_commit(b, 1);
		}
	}
}

void buffer_append_string_c_escaped(buffer *b, const char *s, size_t s_len) {
	unsigned char *ds, *d;
	size_t d_len, ndx;

	force_assert(NULL != b);
	force_assert(NULL != s || 0 == s_len);

	if (0 == s_len) return;

	/* count to-be-encoded-characters */
	for (ds = (unsigned char *)s, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) {
		if ((*ds < 0x20) /* control character */
				|| (*ds >= 0x7f)) { /* DEL + non-ASCII characters */
			switch (*ds) {
			case '\t':
			case '\r':
			case '\n':
				d_len += 2;
				break;
			default:
				d_len += 4; /* \xCC */
				break;
			}
		} else {
			d_len++;
		}
	}

	d = (unsigned char*) buffer_string_prepare_append(b, d_len);

	for (ds = (unsigned char *)s, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) {
		if ((*ds < 0x20) /* control character */
				|| (*ds >= 0x7f)) { /* DEL + non-ASCII characters */
			if (buffer_get_contigous_space(b->used - 1) < 1) {
				buffer_commit(b, 
				buffer_get_contigous_space(b->used - 1));
				d = (unsigned char*)buffer_get_byte_addr(b, b->used - 1);
			}
			d[d_len++] = '\\';
			buffer_commit(b, 1);
			switch (*ds) {
			case '\t':
				if (buffer_get_contigous_space(b->used - 1) < 1) {
					buffer_commit(b, 
					buffer_get_contigous_space(b->used - 1));
					d = (unsigned char*)buffer_get_byte_addr(b, b->used - 1);
				}
				d[0] = 't';
				buffer_commit(b, 1);
				break;
			case '\r':
				if (buffer_get_contigous_space(b->used - 1) < 1) {
					buffer_commit(b, 
					buffer_get_contigous_space(b->used - 1));
					d = (unsigned char*)buffer_get_byte_addr(b, b->used - 1);
				}
				d[0] = 'r';
				buffer_commit(b, 1);
				break;
			case '\n':
				if (buffer_get_contigous_space(b->used - 1) < 1) {
					buffer_commit(b, 
					buffer_get_contigous_space(b->used - 1));
					d = (unsigned char*)buffer_get_byte_addr(b, b->used - 1);
				}
				d[0] = 'n';
				buffer_commit(b, 1);
				break;
			default:
				if (buffer_get_contigous_space(b->used - 1) < 3) {
					buffer_commit(b, 
					buffer_get_contigous_space(b->used - 1));
					d = (unsigned char*)buffer_get_byte_addr(b, b->used - 1);
				}
				d[0] = 'x';
				d[1] = hex_chars[((*ds) >> 4) & 0x0F];
				d[2] = hex_chars[(*ds) & 0x0F];
				buffer_commit(b, 3);
				break;
			}
		} else {
			if (buffer_get_contigous_space(b->used - 1) < 1) {
				buffer_commit(b, 
				buffer_get_contigous_space(b->used - 1));
				d = (unsigned char*)buffer_get_byte_addr(b, b->used - 1);
			}
			d[0] = *ds;
			buffer_commit(b, 1);
		}
	}
}


void buffer_copy_string_encoded_cgi_varnames(buffer *b, const char *s, size_t s_len, int is_http_header) {
	size_t i, j;

	force_assert(NULL != b);
	force_assert(NULL != s || 0 == s_len);

	buffer_reset(b);

	if (is_http_header && NULL != s && 0 != strcasecmp(s, "CONTENT-TYPE")) {
		buffer_string_prepare_append(b, s_len + 5);
		buffer_copy_string_len(b, CONST_STR_LEN("HTTP_"));
	} else {
		buffer_string_prepare_append(b, s_len);
	}

	j = buffer_string_length(b);
	char *p = buffer_get_byte_addr(b, j);
	if (buffer_get_contigous_space(j) == 0) {
		p = buffer_get_byte_addr(b, ++j);
		ipaugenblick_set_buffer_data_len(
				b->bufs_and_desc[j/1448].pdesc,
				ipaugenblick_get_buffer_data_len(
				b->bufs_and_desc[j/1448].pdesc)+1);
	}
	for (i = 0; i < s_len; ++i) {
		unsigned char cr = s[i];	
		if (light_isalpha(cr)) {
			/* upper-case */
			cr &= ~32;
		} else if (!light_isdigit(cr)) {
			cr = '_';
		}
		*p = cr;
		p++;
		if (buffer_get_contigous_space(j - 1) == 0)
			p = buffer_get_byte_addr(b, j);
	}
	b->used = j+1;
	p = buffer_get_byte_addr(b, j);
	*p = '\0';
	ipaugenblick_set_buffer_data_len(
				b->bufs_and_desc[j/1448].pdesc,
				ipaugenblick_get_buffer_data_len(
				b->bufs_and_desc[j/1448].pdesc)+1);
}

/* decodes url-special-chars inplace.
 * replaces non-printable characters with '_'
 */

static void buffer_urldecode_internal(buffer *url, int is_query) {
	unsigned char high, low;
	char *src;
	char *dst;
	int delta = 0;

	force_assert(NULL != url);
	if (buffer_string_is_empty(url)) return;

	force_assert('\0' == *buffer_get_byte_addr(url, url->used-1));
	size_t src_idx = 0, dst_idx = 0;
	src = buffer_get_byte_addr(url, 0);

	while ('\0' != *src) {
		if ('%' == *src) break;
		if (is_query && '+' == *src) *src = ' ';
		src_idx++;
		if (0 == buffer_get_contigous_space(src_idx)) {
			src = buffer_get_byte_addr(url, ++src_idx);
	}
	dst = src;
	dst_idx = src_idx;

	while ('\0' != *src) {
		if (is_query && *src == '+') {
			*dst = ' ';
		} else if (*src == '%') {
			*dst = '%';

			high = hex2int(*(src + 1));
			if (0xFF != high) {
				low = hex2int(*(src + 2));
				if (0xFF != low) {
					high = (high << 4) | low;

					/* map control-characters out */
					if (high < 32 || high == 127) high = '_';

					*dst = high;
					if(buffer_get_contigous_space(src_idx) < 2)
						src = buffer_get_byte_addr(url, src_idx + 2);
					else
						src += 2;
					src_idx += 2;
				}
			}
		} else {
			*dst = *src;
		}
		if(buffer_get_contigous_space(src_idx) == 0) {
			src = buffer_get_byte_addr(url, ++src_idx);
		} else
			src++;
		if(buffer_get_contigous_space(dst_idx) == 0) {
			dst = buffer_get_byte_addr(url, ++dst_idx);
		} else
			dst++;
			dst_idx++;
			delta++;
		}
	}

	*dst = '\0';
	url->used = dst_idx;
	ipaugenblick_set_buffer_data_len(
				url->bufs_and_desc[dst_idx].pdesc,
				ipaugenblick_get_buffer_data_len(
				url->bufs_and_desc[dst_idx].pdesc)+delta);
}

void buffer_urldecode_path(buffer *url) {
	buffer_urldecode_internal(url, 0);
}

void buffer_urldecode_query(buffer *url) {
	buffer_urldecode_internal(url, 1);
}

/* Remove "/../", "//", "/./" parts from path,
 * strips leading spaces,
 * prepends "/" if not present already
 *
 * /blah/..         gets  /
 * /blah/../foo     gets  /foo
 * /abc/./xyz       gets  /abc/xyz
 * /abc//xyz        gets  /abc/xyz
 *
 * NOTE: src and dest can point to the same buffer, in which case,
 *       the operation is performed in-place.
 */

void buffer_path_simplify(buffer *dest, buffer *src)
{
	int toklen;
	char c, pre1;
	char *start, *slash, *walk, *out;
	size_t walk_idx = 0,out_idx = 0;
	unsigned short pre;

	force_assert(NULL != dest && NULL != src);

	if (buffer_string_is_empty(src)) {
		buffer_string_prepare_copy(dest, 0);
		return;
	}

	force_assert('\0' == *buffer_get_byte_addr(src, src->used-1));

	/* might need one character more for the '/' prefix */
	if (src == dest) {
		buffer_string_prepare_append(dest, 1);
	} else {
		buffer_string_prepare_copy(dest, buffer_string_length(src) + 1);
	}

#if defined(__WIN32) || defined(__CYGWIN__)
	/* cygwin is treating \ and / the same, so we have to that too */
	{
		char *p;
		for (p = src->ptr; *p; p++) {
			if (*p == '\\') *p = '/';
		}
	}
#endif

	walk  = buffer_get_byte_addr(src, 0);
	start = buffer_get_byte_addr(dest, 0);
	out   = buffer_get_byte_addr(dest, 0);
	slash = buffer_get_byte_addr(dest, 0);
	walk_idx = 0;

	while (*walk == ' ') {
		if(buffer_get_contigous_space(walk_idx) == 0)
			walk = buffer_get_byte_addr(src, ++walk_idx);
		else {
			walk++;
			walk_idx++;
		}
	}

	pre1 = *walk;
	if(buffer_get_contigous_space(walk_idx) == 0)
		walk = buffer_get_byte_addr(src, ++walk_idx);
	else {
		walk++;
		walk_idx++;
	}
	c    = *(walk++);
	if(buffer_get_contigous_space(walk_idx) == 0)
		walk = buffer_get_byte_addr(src, ++walk_idx);
	else {
		walk++;
		walk_idx++;
	}
	pre  = pre1;
	if (pre1 != '/') {
		pre = ('/' << 8) | pre1;
		*out = '/';
		if(buffer_get_contigous_space(out_idx) == 0)
			out = buffer_get_byte_addr(dest, ++out_idx);
		else {
			out++;
			out_idx++;
		}
	}
	*out = pre1;
	if(buffer_get_contigous_space(out_idx) == 0)
		out = buffer_get_byte_addr(dest, ++out_idx);
	else {
		out++;
		out_idx++;
	}

	if (pre1 == '\0') {
		dest->used = (out - start) + 1;
		return;
	}

	for (;;) {
		if (c == '/' || c == '\0') {
			toklen = out - slash;
			if (toklen == 3 && pre == (('.' << 8) | '.')) {
				out = slash;
				if (out > start) {
					out_idx--;	
					out = buffer_get_byte_addr(dest, out_idx);
					while (out > start && *out != '/') {
						out_idx--;
						out = buffer_get_byte_addr(dest, out_idx);
					}
				}

				if (c == '\0') {
					if(buffer_get_contigous_space(out_idx) == 0)
						out = buffer_get_byte_addr(dest, ++out_idx);
					else {
						out++;
						out_idx++;
					}
				}
			} else if (toklen == 1 || pre == (('/' << 8) | '.')) {
				out = slash;
				if (c == '\0') {
					if(buffer_get_contigous_space(out_idx) == 0)
						out = buffer_get_byte_addr(dest, ++out_idx);
					else {
						out++;
						out_idx++;
					}
				}
			}

			slash = out;
		}

		if (c == '\0') break;

		pre1 = c;
		pre  = (pre << 8) | pre1;
		c    = *walk;
		*out = pre1;

		if(buffer_get_contigous_space(out_idx) == 0)
			out = buffer_get_byte_addr(dest, ++out_idx);
		else {
			out++;
			out_idx++;
		}
		if(buffer_get_contigous_space(walk_idx) == 0)
			walk = buffer_get_byte_addr(src, ++walk_idx);
		else {
			walk++;
			walk_idx++;
		}
	}

	buffer_string_set_length(dest, out - start);
}

int light_isdigit(int c) {
	return (c >= '0' && c <= '9');
}

int light_isxdigit(int c) {
	if (light_isdigit(c)) return 1;

	c |= 32;
	return (c >= 'a' && c <= 'f');
}

int light_isalpha(int c) {
	c |= 32;
	return (c >= 'a' && c <= 'z');
}

int light_isalnum(int c) {
	return light_isdigit(c) || light_isalpha(c);
}

void buffer_to_lower(buffer *b) {
	size_t i;

	char *p = buffer_get_byte_addr(b, 0);
	for (i = 0; i < b->used; ) {
		char c = *p;
		if (c >= 'A' && c <= 'Z') *p |= 0x20;
		if(buffer_get_contigous_space(i) == 0)
			p = buffer_get_byte_addr(b, ++i);
		else {
			p++;
			i++;
		}
	}
}


void buffer_to_upper(buffer *b) {
	size_t i;

	char *p = buffer_get_byte_addr(b, 0);

	for (i = 0; i < b->used; ++i) {
		char c = *p;
		if (c >= 'A' && c <= 'Z') *p &= ~0x20;
		if(buffer_get_contigous_space(i) == 0)
			p = buffer_get_byte_addr(b, ++i);
		else {
			p++;
			i++;
		}
	}
}

#ifdef HAVE_LIBUNWIND
# define UNW_LOCAL_ONLY
# include <libunwind.h>

void print_backtrace(FILE *file) {
	unw_cursor_t cursor;
	unw_context_t context;
	int ret;
	unsigned int frame = 0;

	if (0 != (ret = unw_getcontext(&context))) goto error;
	if (0 != (ret = unw_init_local(&cursor, &context))) goto error;

	fprintf(file, "Backtrace:\n");

	while (0 < (ret = unw_step(&cursor))) {
		unw_word_t proc_ip = 0;
		unw_proc_info_t procinfo;
		char procname[256];
		unw_word_t proc_offset = 0;

		if (0 != (ret = unw_get_reg(&cursor, UNW_REG_IP, &proc_ip))) goto error;

		if (0 == proc_ip) {
			/* without an IP the other functions are useless; unw_get_proc_name would return UNW_EUNSPEC */
			++frame;
			fprintf(file, "%u: (nil)\n", frame);
			continue;
		}

		if (0 != (ret = unw_get_proc_info(&cursor, &procinfo))) goto error;

		if (0 != (ret = unw_get_proc_name(&cursor, procname, sizeof(procname), &proc_offset))) {
			switch (-ret) {
			case UNW_ENOMEM:
				memset(procname + sizeof(procname) - 4, '.', 3);
				procname[sizeof(procname) - 1] = '\0';
				break;
			case UNW_ENOINFO:
				procname[0] = '?';
				procname[1] = '\0';
				proc_offset = 0;
				break;
			default:
				snprintf(procname, sizeof(procname), "?? (unw_get_proc_name error %d)", -ret);
				break;
			}
		}

		++frame;
		fprintf(file, "%u: %s (+0x%x) [%p]\n",
			frame,
			procname,
			(unsigned int) proc_offset,
			(void*)(uintptr_t)proc_ip);
	}

	if (0 != ret) goto error;

	return;

error:
	fprintf(file, "Error while generating backtrace: unwind error %i\n", (int) -ret);
}
#else
void print_backtrace(FILE *file) {
	UNUSED(file);
}
#endif

void log_failed_assert(const char *filename, unsigned int line, const char *msg) {
	/* can't use buffer here; could lead to recursive assertions */
	fprintf(stderr, "%s.%d: %s\n", filename, line, msg);
	print_backtrace(stderr);
	fflush(stderr);
	abort();
}
