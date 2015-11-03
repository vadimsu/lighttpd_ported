#include "network_backends.h"

#include "network.h"
#include "log.h"

#include "sys-socket.h"

#include <unistd.h>

#include <errno.h>
#include <string.h>
#include <ipaugenblick_api.h>

int network_write_mem_chunk(server *srv, connection *con, int fd, chunkqueue *cq, off_t *p_max_bytes) {
	chunk* const c = cq->first;
	off_t c_len;
	ssize_t r;
	UNUSED(con);

	force_assert(NULL != c);
	force_assert(MEM_CHUNK == c->type);
	force_assert(c->offset >= 0 && c->offset <= (off_t)buffer_string_length(c->mem));

	c_len = buffer_string_length(c->mem) - c->offset;
	if (c_len > *p_max_bytes) c_len = *p_max_bytes;

	if (0 == c_len) {
		chunkqueue_remove_finished_chunks(cq);
		return 0;
	}

#if defined(__WIN32)
	if ((r = send(fd, c->mem->ptr + c->offset, c_len, 0)) < 0) {
		int lastError = WSAGetLastError();
		switch (lastError) {
		case WSAEINTR:
		case WSAEWOULDBLOCK:
			break;
		case WSAECONNRESET:
		case WSAETIMEDOUT:
		case WSAECONNABORTED:
			return -2;
		default:
			log_error_write(srv, __FILE__, __LINE__, "sdd",
				"send failed: ", lastError, fd);
			return -1;
		}
	}
#else /* __WIN32 */
	if ((r = write(fd, c->mem->ptr + c->offset, c_len)) < 0) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			break;
		case EPIPE:
		case ECONNRESET:
			return -2;
		default:
			log_error_write(srv, __FILE__, __LINE__, "ssd",
				"write failed:", strerror(errno), fd);
			return -1;
		}
	}
#endif /* __WIN32 */

	if (r >= 0) {
		*p_max_bytes -= r;
		chunkqueue_mark_written(cq, r);
	}

	return (r > 0 && r == c_len) ? 0 : -3;
}

int network_write_chunkqueue_write(server *srv, connection *con, int fd, chunkqueue *cq, off_t max_bytes) {
	int buffer_count = 0, i;
	chunk* c = cq->first;
	while (max_bytes > 0 && c) {

		switch (cq->first->type) {
		case MEM_CHUNK:
			max_bytes -= c->mem->used;
			buffer_count+=c->mem->buffers_count;
			break;
		case FILE_CHUNK:
		//	r = network_write_file_chunk_mmap(srv, con, fd, cq, &max_bytes);
			break;
		}
		c = c->next;
	}
	c = cq->first;
	chunk* next;
	for(i = 0; i < buffer_count && c;) {
		printf("%s %d %d %d %p\n",__FILE__,__LINE__,c->mem ? c->mem->used : -1, c->mem ? c->mem->buffers_count : -1, c->next);
		next = c->next;
		int offsets[c->mem->buffers_count];
		int lengths[c->mem->buffers_count];
		for(int j = 0;j < c->mem->buffers_count;j++) {
		/* VADIM TODO: imcrement refcnt??? */
			offsets[j] = c->offset;
			lengths[j] = ipaugenblick_get_buffer_data_len(c->mem->bufs_and_desc[j].pdesc);
		}
		ipaugenblick_send_bulk(fd, c->mem->bufs_and_desc, offsets, lengths, c->mem->buffers_count);
		while(ipaugenblick_socket_kick(fd) != 0);
		i += c->mem->buffers_count;
		chunkqueue_mark_written(cq, c->mem->used);
		c = next;
	}	
	return 0;
}

int network_write_chunkqueue_sendfile(server *srv, connection *con, int fd, chunkqueue *cq, off_t max_bytes) {
	while (max_bytes > 0 && NULL != cq->first) {
		int r = -1;

		switch (cq->first->type) {
		case MEM_CHUNK:
			r = network_writev_mem_chunks(srv, con, fd, cq, &max_bytes);
			break;
		case FILE_CHUNK:
			r = network_write_file_chunk_sendfile(srv, con, fd, cq, &max_bytes);
			break;
		}

		if (-3 == r) return 0;
		if (0 != r) return r;
	}

	return 0;
}
