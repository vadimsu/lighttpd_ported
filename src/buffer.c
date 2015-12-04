#include "buffer.h"

#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <assert.h>
#include <ctype.h>

#define BUFFER_SPACE 1448

#define MOVE_TO_NEXT_MBUF(buf, mbuf_idx, p_c, sp) \
if (((mbuf_idx)+1) < (buf)->buffers_count) {\
	(p_c) = (buf)->bufs_and_desc[++(mbuf_idx)].pdata; \
	(sp) = ipaugenblick_get_buffer_data_len( \
					(buf)->bufs_and_desc[(mbuf_idx)].pdesc); \
}

#define MOVE_TO_NEXT_EMPTY_MBUF(buf, mbuf_idx, p_c, sp) \
if (((mbuf_idx)+1) < (buf)->buffers_count) {\
	(p_c) = (buf)->bufs_and_desc[++(mbuf_idx)].pdata; \
	(sp) = BUFFER_SPACE; \
}

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
#ifdef USE_MEMPOOLS
void *g_buffer_pool = NULL;
void *g_sg_buffer_pool = NULL;

void buffer_pool_init()
{
	int i;
	void *mem;
	g_buffer_pool = ipaugenblick_create_ring("bufpool", LIGHTTPD_BUFFER_NUMBER);
	force_assert(g_buffer_pool);
	g_sg_buffer_pool = ipaugenblick_create_ring("sgbufpool", LIGHTTPD_SG_BUFFER_NUMBER);	
	force_assert(g_sg_buffer_pool);
	
	for(i = 0;i < LIGHTTPD_BUFFER_NUMBER;i++) {
		mem = ipaugenblick_mem_get(sizeof(buffer));
		force_assert(mem);
		ipaugenblick_ring_free(g_buffer_pool, mem);
	}
	for(i = 0;i < LIGHTTPD_SG_BUFFER_NUMBER;i++) {
		mem = ipaugenblick_mem_get(sizeof(struct data_and_descriptor)*16);
		force_assert(mem);
		ipaugenblick_ring_free(g_sg_buffer_pool, mem);
	}	
}
#endif
buffer* buffer_init(void) {
	buffer *b;
#ifdef USE_MEMPOOLS
	force_assert(g_buffer_pool);
	b = (buffer *)ipaugenblick_ring_get(g_buffer_pool);
#else
	b = malloc(sizeof(*b));
#endif
	force_assert(b);

	b->ptr = NULL;
	b->size = 0;
	b->used = 0;
	b->current_buffer_idx = 0;
	b->p_current = NULL;
	b->buffers_count = 0;
	b->bufs_and_desc = NULL;
	b->is_rx = 0;

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
		if (b->is_rx) {
			ipaugenblick_release_rx_buffer(b->bufs_and_desc[i].pdesc, b->fd);
		}
		else {
			ipaugenblick_release_tx_buffer(b->bufs_and_desc[i].pdesc);
		}
	}
	if (b->bufs_and_desc) {
#ifdef USE_MEMPOOLS
		ipaugenblick_ring_free(g_sg_buffer_pool, b->bufs_and_desc);
#else
		free(b->bufs_and_desc);
#endif
		b->bufs_and_desc = NULL;
	}
	b->buffers_count = 0;
	b->is_rx = 0;
#ifdef USE_MEMPOOLS
	ipaugenblick_ring_free(g_buffer_pool, b);
#else
        free(b);
#endif
}

void buffer_reset(buffer *b) {
	if (NULL == b) return;

	/* limit don't reuse buffer larger than ... bytes */
	int idx;

	for(idx = 0; idx < b->buffers_count; idx++)
		if (b->is_rx) {
			ipaugenblick_release_rx_buffer(b->bufs_and_desc[idx].pdesc, b->fd);
		}
		else {
			ipaugenblick_release_tx_buffer(b->bufs_and_desc[idx].pdesc);
		}
	b->ptr = NULL;
	b->size = 0;
	b->used = 0;
	b->current_buffer_idx = 0;
	b->p_current = NULL;
	if (b->bufs_and_desc) {
#ifdef USE_MEMPOOLS
		ipaugenblick_ring_free(g_sg_buffer_pool, b->bufs_and_desc);
#else
		free(b->bufs_and_desc);
#endif
		b->bufs_and_desc = NULL;
	}
	b->buffers_count = 0;
	b->is_rx = 0;
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
	b->is_rx = 0;
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
	force_assert(b->is_rx == 0);
	if (0 == size) size = 1;

	if (size <= (b->size - b->used)) return;

	if(b->ptr != NULL) {
		buffer_realloc(b, size);
		return;
	}

	b->used = 0;
	b->current_buffer_idx = 0;
	number_of_buffers = size / BUFFER_SPACE + ((size%BUFFER_SPACE) != 0);
	force_assert(number_of_buffers <= 16);
#ifdef USE_MEMPOOLS
	b->bufs_and_desc = ipaugenblick_ring_get(g_sg_buffer_pool);
#else
	b->bufs_and_desc = calloc(number_of_buffers, sizeof(b->bufs_and_desc[0]));
#endif
	force_assert(b->bufs_and_desc);
	force_assert(ipaugenblick_get_buffers_bulk(size, 
						-1, 
						number_of_buffers, 
						b->bufs_and_desc) == 0);
	b->buffers_count = number_of_buffers;
	b->size = /*size*/b->buffers_count*BUFFER_SPACE;
	b->ptr = b->bufs_and_desc[0].pdata;
	b->p_current = b->ptr;
	force_assert(NULL != b->ptr);
}

buffer *buffer_alloc_for_binary(int size)
{
	buffer *b = buffer_init();
	b->used = 0;
	b->current_buffer_idx = 0;
	b->p_current = NULL;
	b->buffers_count = size / BUFFER_SPACE + ((size%BUFFER_SPACE) != 0);
	force_assert(b->buffers_count <= 16);
#ifdef USE_MEMPOOLS
	b->bufs_and_desc = ipaugenblick_ring_get(g_sg_buffer_pool);
#else
	b->bufs_and_desc = calloc(b->buffers_count, sizeof(b->bufs_and_desc[0]));
#endif
	force_assert(b->bufs_and_desc);
	b->size = /*size*/b->buffers_count*BUFFER_SPACE;
	b->is_rx = 1;
	return b;
}

/* make sure buffer is at least "size" big. keep old data */
static void buffer_realloc(buffer *b, size_t size) {
	int number_of_buffers;
	force_assert(NULL != b);

	if (0 == size) size = 1;

	if (size <= (b->size - b->used)) return;

	int delta = size - (b->size - b->used);
	number_of_buffers = delta / BUFFER_SPACE + ((delta%BUFFER_SPACE) != 0);
	struct data_and_descriptor *bufs_and_desc = b->bufs_and_desc;
	int old_number_of_buffers = b->buffers_count;
	force_assert((old_number_of_buffers + number_of_buffers) <= 16);

	//b->bufs_and_desc = ipaugenblick_ring_get(g_sg_buffer_pool);
	//memcpy(b->bufs_and_desc, bufs_and_desc, sizeof(*bufs_and_desc)*old_number_of_buffers);
	force_assert(ipaugenblick_get_buffers_bulk(
			size,
			-1, 
			number_of_buffers,
			&b->bufs_and_desc[b->buffers_count]) == 0);
	b->buffers_count += number_of_buffers;
	b->size = /*size*/b->buffers_count*BUFFER_SPACE;
	if (b->ptr == NULL)
		b->ptr = b->bufs_and_desc[0].pdata;
	force_assert(NULL != b->ptr);
}


char* buffer_string_prepare_copy(buffer *b, size_t size) {
	force_assert(NULL != b);
	force_assert(size + 1 > size);

	buffer_alloc(b, size + 1);
	b->ptr = b->bufs_and_desc[0].pdata;
	b->p_current = b->ptr;
	b->current_buffer_idx = 0;
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

		return b->p_current;
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
	size_t space = 0;
	force_assert(NULL != b);
	force_assert(b->size > 0);

	if (0 == b->used) {
		ipaugenblick_set_buffer_data_len(
					b->bufs_and_desc[0].pdesc,
					1);
		b->used = 1;
		b->current_buffer_idx = 0;
		b->p_current = b->bufs_and_desc[0].pdata;
	}
	if (size > 0)
		space = BUFFER_SPACE - ipaugenblick_get_buffer_data_len(b->bufs_and_desc[b->current_buffer_idx].pdesc);
	while (size > 0) {
		/* check for overflow: unsigned overflow is defined to wrap around */
		force_assert(b->used + size > b->used);
		force_assert(b->used + size <= b->size);	
		b->used += size;
		if (space <= size) {
//			b->used += space;
			size -= space;
			ipaugenblick_set_buffer_data_len(
					b->bufs_and_desc[b->current_buffer_idx].pdesc,
					BUFFER_SPACE);
			b->current_buffer_idx++;
			b->p_current = b->bufs_and_desc[b->current_buffer_idx].pdata;
			space = BUFFER_SPACE;
		} else {
			int current_length = 
				ipaugenblick_get_buffer_data_len(
					b->bufs_and_desc[b->current_buffer_idx].pdesc);
//			b->used += size;
			b->p_current += size;
			ipaugenblick_set_buffer_data_len(
				b->bufs_and_desc[b->current_buffer_idx].pdesc,
				current_length + size);
			space -= size;
			size = 0;
		}
	}
	*(b->p_current) = '\0';
}

int buffer_strlen(buffer *b)
{
	int i;
	int len = 0;
	for(i = 0; i < b->buffers_count;i++) {
		int len2 = ipaugenblick_get_buffer_data_len(b->bufs_and_desc[i].pdesc);
		len += len2;
		if (len2 < BUFFER_SPACE)
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
	char *p = b->bufs_and_desc[0].pdata;
	int idx = 0;
	int dst_remains = BUFFER_SPACE;
	while(copied < s_len) {	
		if ((s_len - copied) > dst_remains) {
			memcpy(p, s + copied, dst_remains);
			copied += dst_remains;
			MOVE_TO_NEXT_EMPTY_MBUF(b, idx, p , dst_remains);
		} else {
			memcpy(p, s + copied, (s_len - copied));
			p += (s_len - copied);
			copied += (s_len - copied);
			dst_remains = (s_len - copied);
		}	
	}

	buffer_commit(b, s_len);
	dump_buffer(b);
}

void buffer_copy_buffer(buffer *b, const buffer *src) {
	if (NULL == src || 0 == src->used) {
		buffer_string_prepare_copy(b, 0);
		b->used = 0; /* keep special empty state for now */
		b->current_buffer_idx = 0;
	} else {
		size_t copied = 0;
		size_t tocopy = buffer_string_length(src);
		buffer_string_prepare_copy(b, tocopy);
		char *p_src = src->bufs_and_desc[0].pdata;
		char *p_dst = b->bufs_and_desc[0].pdata;
		int src_idx = 0;
		int dst_idx = 0;
		int dst_remains = BUFFER_SPACE;
		int src_remains = ipaugenblick_get_buffer_data_len(
					src->bufs_and_desc[0].pdesc);
		while(copied < tocopy) {
			size_t tocopy2 = (tocopy - copied > src_remains) ? src_remains : (tocopy - copied);
			tocopy2 = (tocopy2 > dst_remains) ? dst_remains : tocopy2;
			memcpy(p_dst, p_src, tocopy2);
			if (tocopy2 == dst_remains) {
				MOVE_TO_NEXT_EMPTY_MBUF(b,dst_idx, p_dst , dst_remains);
			} else {
				p_dst += tocopy2;
				dst_remains -= tocopy2;
			}
			if (tocopy2 == src_remains) {
				MOVE_TO_NEXT_MBUF(src, src_idx, p_src , src_remains);
			} else {
				p_src += tocopy2;
				src_remains -= tocopy2;
			}
			copied += tocopy2;
		}
		buffer_commit(b, tocopy);
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
	target_buf = buffer_string_prepare_append(b, s_len - copied);
	size_t space = BUFFER_SPACE - ipaugenblick_get_buffer_data_len(b->bufs_and_desc[b->current_buffer_idx].pdesc);
	while(copied < s_len) {	
		int tocopy = ((s_len - copied) > space) ? space : s_len - copied;
		memcpy(target_buf,s + copied, tocopy);
		buffer_commit(b, tocopy);
		if (tocopy == space) {
			target_buf = buffer_string_prepare_append(b, s_len - copied);
			space = ipaugenblick_get_buffer_data_len(b->bufs_and_desc[b->current_buffer_idx].pdesc);
		} else {
			space -= tocopy;
			target_buf += tocopy;
		}
		copied += tocopy;
	}
	if (b->used > 0) {
		*(b->p_current) = '\0';
	}
	dump_buffer(b);
}

void buffer_append_string_buffer(buffer *b, const buffer *src) {
	if (NULL == src) {
		buffer_append_string_len(b, NULL, 0);
	} else {
		int copied = 0;
		int idx = 0;
		int tocopy = buffer_string_length(src);
		char *p = src->bufs_and_desc[idx].pdata;
		size_t space_src = ipaugenblick_get_buffer_data_len(src->bufs_and_desc[idx].pdesc);
		while(copied < tocopy) {
			size_t tocopy2 = (tocopy - copied) > space_src ? space_src : (tocopy - copied);

			buffer_append_string_len(b, p, tocopy2);
			if (tocopy2 == space_src) {
				MOVE_TO_NEXT_MBUF(src, idx, p , space_src);
			}
			copied += tocopy2;
		}
	}
	if (b->used > 0) {
		*(b->p_current) = '\0';
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
	size_t space = BUFFER_SPACE - ipaugenblick_get_buffer_data_len(b->bufs_and_desc[b->current_buffer_idx].pdesc);
//	buffer_commit(b, shift); /* will fill below */

	shift <<= 2; /* count bits now */
	size_t copied = 0;
	while (shift > 0) {
		shift -= 4;
		if (copied == space) {
			buffer_commit(b, copied);
			MOVE_TO_NEXT_EMPTY_MBUF(b, b->current_buffer_idx, buf , space);
			space = BUFFER_SPACE - space;
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
	b->current_buffer_idx = 0;
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
	size_t space = BUFFER_SPACE - ipaugenblick_get_buffer_data_len(b->bufs_and_desc[b->current_buffer_idx].pdesc);
	r = strftime(buf, space, format, tm);

	/* 0 (in some apis buffer_string_space(b)) signals the string may have
	 * been too small; but the format could also just have lead to an empty
	 * string
	 */
	if (0 == r || r >= space) {
		/* give it a second try with a larger string */
		buffer_string_prepare_append(b, BUFFER_SPACE);
		MOVE_TO_NEXT_MBUF(b, b->current_buffer_idx, buf , space);
		space = BUFFER_SPACE - space;
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
	size_t tocompare = len > BUFFER_SPACE ? BUFFER_SPACE : len;
	for(i = 0, p = buffer_get_byte_addr(b, i); i < b->used - remaining;) {	
		
		if (0 == memcmp(p, needle, tocompare)) {
			remaining -= tocompare;
			if (remaining == 0)
				return buffer_get_byte_addr(b, i);
		} else {
			remaining = len;
		}
		if ((i%BUFFER_SPACE) == 0) {
			p = buffer_get_byte_addr(b, i);
			tocompare = remaining > BUFFER_SPACE ? BUFFER_SPACE : remaining;
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
	char *p1, *p2;
	int idx1 = 0, idx2 = 0;
	size_t compared = 0;
	force_assert(NULL != a && NULL != b);

	if (a->used != b->used) return 0;
	if (a->used == 0) return 1;
	p1 = a->ptr;
	p2 = b->ptr;
	int curr_len1 = ipaugenblick_get_buffer_data_len(a->bufs_and_desc[idx1].pdesc);
	int curr_len2 = ipaugenblick_get_buffer_data_len(a->bufs_and_desc[idx2].pdesc);
	while(compared < a->used) {
		size_t tocompare = ((a->used - compared) > curr_len1) ? curr_len1 : (a->used - compared);
		if (tocompare > curr_len2)
			tocompare = curr_len2;

		if (memcmp(p1, p2, tocompare))
			break;
		if (tocompare == curr_len1) {
			MOVE_TO_NEXT_MBUF(a, idx1, p1 , curr_len1);
		} else {
			p1 += tocompare;
			curr_len1 -= tocompare;
		}
		if (tocompare == curr_len2) {
			MOVE_TO_NEXT_MBUF(b, idx2, p2 , curr_len2);
		} else {
			p2 += tocompare;
			curr_len2 -= tocompare;
		}
		compared += tocompare;
	}

	return (compared == a->used);
}

int buffer_is_equal_string(const buffer *a, const char *s, size_t b_len) {
	size_t compared = 0;
	char *p;
	int idx = 0;
	force_assert(NULL != a && NULL != s);
//	force_assert(b_len + 1 > b_len);

	if (a->used != b_len + 1) return 0;
	p = a->ptr;
	int curr_len = ipaugenblick_get_buffer_data_len(a->bufs_and_desc[0].pdesc);
	while(compared < b_len) {
		
		size_t tocompare = ((b_len - compared) > curr_len) ?  curr_len : (b_len - compared);
		
		if (memcmp(p, s + compared, tocompare)) {
			break;
		}
/*		if (a->used <= tocompare) {
			break;
		}*/
		compared += tocompare;
		if ((tocompare == curr_len)&&(compared < b_len)) {
			MOVE_TO_NEXT_MBUF(a, idx, p , curr_len);
			if (curr_len == 0)
				break;
		} else
			break;
//		s += tocompare;
	}
	if ('\0' != *(a->p_current)) return 0;
	return (compared == b_len);
}

/* buffer_is_equal_caseless_string(b, CONST_STR_LEN("value")) */
int buffer_is_equal_caseless_string(const buffer *a, const char *s, size_t b_len) {
	size_t compared = 0;
	char *p;
	int idx = 0;
	int space = 0;
	force_assert(NULL != a);

	if (a->used != b_len + 1) return 0;
//	force_assert('\0' == a->ptr[a->used - 1]);
	p = a->ptr;
	while(compared < a->used) {
		int curr_len = ipaugenblick_get_buffer_data_len(a->bufs_and_desc[idx].pdesc);
		size_t tocompare = ((a->used - compared) > curr_len) ? curr_len : (a->used - compared);

		if (strncasecmp(p, s, tocompare))
			break;
		if (a->used <= tocompare) {
			break;
		}
		MOVE_TO_NEXT_MBUF(a, idx, p , space);
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
	char *p1, *p2;
	int idx1 = 0, idx2 = 0;
	/* no len -> equal */
	if (len == 0) return 1;

	/* len > 0, but empty buffers -> not equal */
	if (b1->used == 0 || b2->used == 0) return 0;

	/* buffers too small -> not equal */
	if (b1->used - 1 < len || b2->used - 1 < len) return 0;

	size_t compared = 0;
	p1 = b1->ptr;
	p2 = b2->ptr;
	int curr_len1 = ipaugenblick_get_buffer_data_len(b1->bufs_and_desc[idx1].pdesc);
	int curr_len2 = ipaugenblick_get_buffer_data_len(b2->bufs_and_desc[idx2].pdesc);
	while(compared < len) {
		size_t tocompare = ((len - compared) > curr_len1) ? curr_len1 : (len - compared);

		if (tocompare > curr_len2)
			tocompare = curr_len2;

		if (memcmp(p1, p2, tocompare))
			break;
		if (tocompare == curr_len1) {
			MOVE_TO_NEXT_MBUF(b1, idx1, p1 , curr_len1);
		} else {
			curr_len1 -= tocompare;
		}
		if (tocompare == curr_len2) {
			MOVE_TO_NEXT_MBUF(b2, idx2, p2 , curr_len2);
		} else {
			curr_len2 -= tocompare;
		}
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
	char *p = b->ptr;
	int idx = 0;
	int space = 0;
	/* overflow protection */
	force_assert(in_len * 2 > in_len);

	buffer_string_set_length(b, 2 * in_len);
	size_t processed = 0;
	while (processed < in_len) {
		int curr_len = ipaugenblick_get_buffer_data_len(b->bufs_and_desc[idx].pdesc);
		size_t toprocess = (in_len - processed) > (BUFFER_SPACE - curr_len) ? (BUFFER_SPACE - curr_len) : (in_len - processed);
		li_tohex(p, in, toprocess);
		in += toprocess;
		processed += toprocess;
		if (toprocess == (BUFFER_SPACE - curr_len)) {
			MOVE_TO_NEXT_MBUF(b, idx, p , space);
		}
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
	int space;

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
	space = BUFFER_SPACE - ipaugenblick_get_buffer_data_len(b->bufs_and_desc[b->current_buffer_idx].pdesc);

	for (ds = (unsigned char *)s, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) {
		if (map[*ds]) {
			switch(encoding) {
			case ENCODING_REL_URI:
			case ENCODING_REL_URI_PART:
				d = (unsigned char*)b->p_current;
				if (space < 3) {
					MOVE_TO_NEXT_EMPTY_MBUF(b, b->current_buffer_idx, d , space);
					b->p_current = b->bufs_and_desc[b->current_buffer_idx].pdata;
				}
				d[0] = '%';
				d[1] = hex_chars[((*ds) >> 4) & 0x0F];
				d[2] = hex_chars[(*ds) & 0x0F];
				space -= 3;
				buffer_commit(b, 3);
				break;
			case ENCODING_HTML:
			case ENCODING_MINIMAL_XML:
				d = (unsigned char*)b->p_current;
				if (space < 6) {
					MOVE_TO_NEXT_EMPTY_MBUF(b, b->current_buffer_idx, d , space);
					b->p_current = b->bufs_and_desc[b->current_buffer_idx].pdata;
				}
				d[0] = '&';
				d[1] = '#';
				d[2] = 'x';
				d[3] = hex_chars[((*ds) >> 4) & 0x0F];
				d[4] = hex_chars[(*ds) & 0x0F];
				d[5] = ';';
				space -= 6;
				buffer_commit(b, 6);
				break;
			case ENCODING_HEX:
				d = (unsigned char*)b->p_current;
				if (space < 2) {
					MOVE_TO_NEXT_EMPTY_MBUF(b, b->current_buffer_idx, d , space);
					b->p_current = b->bufs_and_desc[b->current_buffer_idx].pdata;
				}
				d[0] = hex_chars[((*ds) >> 4) & 0x0F];
				d[1] = hex_chars[(*ds) & 0x0F];
				space -= 2;
				buffer_commit(b, 2);
				break;
			case ENCODING_HTTP_HEADER:
				d = (unsigned char*)b->p_current;
				if (space < 2) {
					MOVE_TO_NEXT_EMPTY_MBUF(b, b->current_buffer_idx, d , space);
					b->p_current = b->bufs_and_desc[b->current_buffer_idx].pdata;
				}
				d[0] = *ds;
				d[1] = '\t';
				space -= 2;
				buffer_commit(b, 2);
				break;
			}
		} else {
			if (space == 0) {
				if (ipaugenblick_get_buffer_data_len(b->bufs_and_desc[b->current_buffer_idx].pdesc) > 0) {
					space = ipaugenblick_get_buffer_data_len(b->bufs_and_desc[b->current_buffer_idx].pdesc);
					d = b->p_current;
					d_len = 0;
				} else {
					MOVE_TO_NEXT_EMPTY_MBUF(b, b->current_buffer_idx, d , space);
					b->p_current = b->bufs_and_desc[b->current_buffer_idx].pdata;
					d_len = 0;
				}
			}
			d[d_len++] = *ds;
			space--;
			buffer_commit(b, 1);
		}
	}
}

void buffer_append_string_c_escaped(buffer *b, const char *s, size_t s_len) {
	unsigned char *ds, *d;
	size_t d_len, ndx;
	int space;

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
	space = BUFFER_SPACE - ipaugenblick_get_buffer_data_len(b->bufs_and_desc[b->current_buffer_idx].pdesc);

	for (ds = (unsigned char *)s, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) {
		if ((*ds < 0x20) /* control character */
				|| (*ds >= 0x7f)) { /* DEL + non-ASCII characters */
			if (space == 0) {
				MOVE_TO_NEXT_EMPTY_MBUF(b, b->current_buffer_idx, d , space);
				d_len = 0;
				b->p_current = b->bufs_and_desc[b->current_buffer_idx].pdata;
			}
			d[d_len++] = '\\';
			space--;
			buffer_commit(b, 1);
			switch (*ds) {
			case '\t':
				if (space == 0) {
					MOVE_TO_NEXT_EMPTY_MBUF(b, b->current_buffer_idx, d , space);
					d_len = 0;
					b->p_current = b->bufs_and_desc[b->current_buffer_idx].pdata;
				}
				d[0] = 't';
				space--;
				buffer_commit(b, 1);
				break;
			case '\r':
				if (space == 0) {
					MOVE_TO_NEXT_EMPTY_MBUF(b, b->current_buffer_idx, d , space);
					d_len = 0;
					b->p_current = b->bufs_and_desc[b->current_buffer_idx].pdata;
				}
				d[0] = 'r';
				space--;
				buffer_commit(b, 1);
				break;
			case '\n':
				if (space == 0) {
					MOVE_TO_NEXT_EMPTY_MBUF(b, b->current_buffer_idx, d , space);
					d_len = 0;
					b->p_current = b->bufs_and_desc[b->current_buffer_idx].pdata;
				}
				d[0] = 'n';
				space--;
				buffer_commit(b, 1);
				break;
			default:
				if (space < 3) {
					MOVE_TO_NEXT_EMPTY_MBUF(b, b->current_buffer_idx, d , space);
					d_len = 0;
					b->p_current = b->bufs_and_desc[b->current_buffer_idx].pdata;
				}
				d[0] = 'x';
				d[1] = hex_chars[((*ds) >> 4) & 0x0F];
				d[2] = hex_chars[(*ds) & 0x0F];
				space -= 3;
				buffer_commit(b, 3);
				break;
			}
		} else {
			if ((space == 0)&&((b->current_buffer_idx+1) < b->buffers_count)) {
				MOVE_TO_NEXT_EMPTY_MBUF(b, b->current_buffer_idx, d , space);
				d_len = 0;
				b->p_current = b->bufs_and_desc[b->current_buffer_idx].pdata;
			}
			d[0] = *ds;
			space--;
			buffer_commit(b, 1);
		}
	}
}


void buffer_copy_string_encoded_cgi_varnames(buffer *b, const char *s, size_t s_len, int is_http_header) {
	size_t i, j;
	int space,idx;

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
	idx = j / BUFFER_SPACE;
	char *p = b->p_current;
	int  remains = BUFFER_SPACE - ipaugenblick_get_buffer_data_len(b->bufs_and_desc[idx].pdesc);
	if (remains == 0) {
		MOVE_TO_NEXT_EMPTY_MBUF(b, idx, p , remains);
		p = b->bufs_and_desc[++idx].pdata;
		ipaugenblick_set_buffer_data_len(
				b->bufs_and_desc[j/BUFFER_SPACE].pdesc,
				ipaugenblick_get_buffer_data_len(
				b->bufs_and_desc[j/BUFFER_SPACE].pdesc)+1);
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
		remains--;
		if (remains == 0) {
			MOVE_TO_NEXT_MBUF(b, idx, p , remains);
		}
	}
	b->used = j+1;
	b->p_current = p;
	b->current_buffer_idx = b->used / BUFFER_SPACE;
	*p = '\0';
	ipaugenblick_set_buffer_data_len(
				b->bufs_and_desc[j/BUFFER_SPACE].pdesc,
				ipaugenblick_get_buffer_data_len(
				b->bufs_and_desc[j/BUFFER_SPACE].pdesc)+1);
}

/* decodes url-special-chars inplace.
 * replaces non-printable characters with '_'
 */

static void buffer_urldecode_internal(buffer *url, int is_query) {
	unsigned char high, low;
	char *src;
	int src_remains = 0, dst_remains;
	char *dst;
	int delta = 0;

	force_assert(NULL != url);
	if (buffer_string_is_empty(url)) return;

//	force_assert('\0' == *buffer_get_byte_addr(url, url->used-1));
	size_t src_idx = 0, dst_idx = 0;
	src = url->ptr;
	src_remains = ipaugenblick_get_buffer_data_len(url->bufs_and_desc[0].pdesc);

	while ('\0' != *src) {
		if ('%' == *src) break;
		if (is_query && '+' == *src) *src = ' ';
		src_idx++;
		src_remains--;
		if (0 == src_remains) {
			MOVE_TO_NEXT_MBUF(url, src_idx, src , src_remains);
			if (src_remains == 0)
				break;
		}
	}
	dst = src;
	dst_idx = src_idx;
	dst_remains = src_remains;

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
					if(src_remains < 2) {
						MOVE_TO_NEXT_MBUF(url, src_idx, src , src_remains);
					} else {
						src += 2;
						src_remains -= 2;
					}
					delta += 2;
				}
			}
		} else {
			*dst = *src;
		}
		src++;
		src_remains--;
		if(src_remains == 0) {
			MOVE_TO_NEXT_MBUF(url, src_idx, src , src_remains);	
		}
		dst++;
		dst_remains--;
		if(dst_remains == 0) {
			MOVE_TO_NEXT_MBUF(url, dst_idx, dst , dst_remains);
		}
		if ((src_remains == 0)||(dst_remains == 0)) {
			break;
		}
	}

	*dst = '\0';

	if (dst_idx < url->buffers_count) {
		while (ipaugenblick_get_buffer_data_len(url->bufs_and_desc[dst_idx].pdesc) < delta) {
			force_assert(ipaugenblick_get_buffer_data_len(url->bufs_and_desc[dst_idx].pdesc));
			ipaugenblick_set_buffer_data_len(url->bufs_and_desc[dst_idx].pdesc, 0);
			delta -= ipaugenblick_get_buffer_data_len(url->bufs_and_desc[dst_idx--].pdesc);
		}
		if (delta > 0) {
			ipaugenblick_set_buffer_data_len(url->bufs_and_desc[dst_idx].pdesc, ipaugenblick_get_buffer_data_len(url->bufs_and_desc[dst_idx].pdesc) - delta);
		}
		url->current_buffer_idx = dst_idx;
		url->used -= delta;
		url->p_current = url->bufs_and_desc[dst_idx].pdata;
	}
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
	size_t walk_idx = 0,out_idx = 0, slash_idx = 0,start_idx = 0;
	size_t walk_remains, out_remains, slash_remains, start_remains;
	unsigned short pre;

	force_assert(NULL != dest && NULL != src);

	if (buffer_string_is_empty(src)) {
		buffer_string_prepare_copy(dest, 0);
		return;
	}

	force_assert('\0' == *src->p_current);

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
	walk  = src->ptr;
	start = dest->ptr;
	out   = dest->ptr;
	slash = dest->ptr;
	walk_remains = 	ipaugenblick_get_buffer_data_len(src->bufs_and_desc[0].pdesc);
	start_remains = BUFFER_SPACE;
	out_remains = BUFFER_SPACE;
	slash_remains = BUFFER_SPACE;
	while (*walk == ' ') {
		walk++;
		walk_remains--;
		if(walk_remains == 0) {
			MOVE_TO_NEXT_MBUF(src, walk_idx, walk , walk_remains);
		}
	}

	pre1 = *(walk++);
	walk_remains--;
	if(walk_remains == 0) {
		MOVE_TO_NEXT_MBUF(src, walk_idx, walk , walk_remains);
	}
	c    = *(walk++);
	walk_remains--;
	if(walk_remains == 0) {
		MOVE_TO_NEXT_MBUF(src, walk_idx, walk , walk_remains);
	}
	pre  = pre1;

	if (pre1 != '/') {
		pre = ('/' << 8) | pre1;
		*out = '/';
		out++;
		out_remains--;
		if(out_remains == 0) {
			MOVE_TO_NEXT_EMPTY_MBUF(dest, out_idx, out , out_remains);
		}
	}
	*out = pre1;
	out++;
	out_remains--;
	if(out_remains == 0) {
		MOVE_TO_NEXT_EMPTY_MBUF(dest, out_idx, out , out_remains);
	}
	if (pre1 == '\0') {
		dest->used = (out - start) + 1;
		dest->current_buffer_idx = dest->used / BUFFER_SPACE;
		return;
	}

	for (;;) {
		if (c == '/' || c == '\0') {
			toklen = out - slash;
			if (toklen == 3 && pre == (('.' << 8) | '.')) {
				out = slash;
				if (out > start) {
					if (out_remains == BUFFER_SPACE) {
						out = dest->bufs_and_desc[--out_idx].pdata + BUFFER_SPACE - 1;
						out_remains = 0;
					} else {
						out_remains++;
						out--;
					}
					while (out > start && *out != '/') {
						if (out_remains == BUFFER_SPACE) {
							out = dest->bufs_and_desc[--out_idx].pdata + BUFFER_SPACE - 1;
							out_remains = 0;
						} else {
							out_remains++;
							out--;
						}
					}
				}

				if (c == '\0') {
					if(out_remains == 0) {
						MOVE_TO_NEXT_EMPTY_MBUF(dest, out_idx, out , out_remains);
					} else {
						out++;
						out_remains--;
					}
				}
			} else if (toklen == 1 || pre == (('/' << 8) | '.')) {
				out = slash;
				if (c == '\0') {
					if(out_remains == 0) {
						MOVE_TO_NEXT_EMPTY_MBUF(dest, out_idx, out , out_remains);
					} else {
						out++;
						out_remains--;
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

		if(out_remains == 0) {
			MOVE_TO_NEXT_EMPTY_MBUF(dest, out_idx, out , out_remains);
		} else {
			out++;
			out_remains--;
		}
		if(walk_remains == 0) {
			MOVE_TO_NEXT_MBUF(src, walk_idx, walk , walk_remains);
		} else {
			walk++;
			walk_remains--;
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

	char *p = b->ptr;
	int idx = 0;
	int space = ipaugenblick_get_buffer_data_len(
					b->bufs_and_desc[0].pdesc);
	for (i = 0; i < b->used; ) {
		char c = *p;
		if (c >= 'A' && c <= 'Z') *p |= 0x20;
		if(space == 0) {
			MOVE_TO_NEXT_MBUF(b, idx, p , space);
		}
		else {
			p++;
			i++;
			space--;
		}
	}
}


void buffer_to_upper(buffer *b) {
	size_t i;

	char *p = b->ptr;
	int idx = 0;
	int space = ipaugenblick_get_buffer_data_len(
					b->bufs_and_desc[0].pdesc);

	for (i = 0; i < b->used; ++i) {
		char c = *p;
		if (c >= 'A' && c <= 'Z') *p &= ~0x20;
		if(space == 0) {
			MOVE_TO_NEXT_MBUF(b, idx, p, space);
		}
		else {
			p++;
			i++;
			space--;
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
