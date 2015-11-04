#include "network_backends.h"

#include "network.h"
#include "log.h"

#include "sys-socket.h"

#include <unistd.h>

#include <errno.h>
#include <string.h>
#include <ipaugenblick_api.h>

int network_ipaugenblick_file_chunk(server *srv, connection *con, int fd, chunkqueue *cq, off_t *p_max_bytes) {
	chunk* const c = cq->first;
	off_t offset, toSend;
	ssize_t r;

	force_assert(NULL != c);
	force_assert(FILE_CHUNK == c->type);
	force_assert(c->offset >= 0 && c->offset <= c->file.length);

	offset = c->file.start + c->offset;
	toSend = c->file.length - c->offset;
	if (toSend > 64*1024) toSend = 64*1024; /* max read 64kb in one step */
	if (toSend > *p_max_bytes) toSend = *p_max_bytes;

	if (0 == toSend) {
		chunkqueue_remove_finished_chunks(cq);
		return 0;
	}

	if (0 != network_open_file_chunk(srv, con, cq)) return -1;

	int buffers_count = toSend / 1448 + ((toSend % 1448) ? 1 : 0);
	struct data_and_descriptor bufs_and_desc[buffers_count];
	int offsets[buffers_count];
	int lengths[buffers_count];
	if (0 != ipaugenblick_get_buffers_bulk(toSend, fd, buffers_count, bufs_and_desc)) {
		return -1;
	}

	if (-1 == lseek(c->file.fd, offset, SEEK_SET)) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "lseek: ", strerror(errno));
		return -1;
	}
	int buf_idx = 0;
	while(toSend > 0) {
		int toRead = (toSend > 1448) ? 1448 : toSend;
		if (-1 == (toSend = read(c->file.fd, bufs_and_desc[buf_idx].pdata, toRead))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "read: ", strerror(errno));
			return -1;
		}
		offsets[buf_idx] = 0;
		lengths[buf_idx] = toRead;
		ipaugenblick_set_buffer_data_len(bufs_and_desc[buf_idx].pdesc, toRead);
//		ipaugenblick_update_rfc(c->mem->bufs_and_desc[i].pdesc, 1);
		buf_idx++;
		toSend -= toRead;
	}

	ipaugenblick_send_bulk(fd, bufs_and_desc, offsets, lengths, buffers_count);
	while(ipaugenblick_socket_kick(fd) != 0);
	chunkqueue_mark_written(cq, toSend);

	return 0;
}

int network_ipaugenblick_chunkqueue_write(server *srv, connection *con, int fd, chunkqueue *cq, off_t max_bytes) {
	int buffer_count = 0, i;
	chunk* next;
	chunk* c = cq->first;
	while (max_bytes > 0 && c) {

		switch (cq->first->type) {
		case MEM_CHUNK:
			max_bytes -= c->mem->used;
			{
				int offsets[c->mem->buffers_count];
				int lengths[c->mem->buffers_count];
				for(i = 0; i < c->mem->buffers_count;i++) {
					offsets[i] = c->offset;
					lengths[i] = ipaugenblick_get_buffer_data_len(c->mem->bufs_and_desc[i].pdesc);
					ipaugenblick_update_rfc(c->mem->bufs_and_desc[i].pdesc, 1);
				}
				ipaugenblick_send_bulk(fd, c->mem->bufs_and_desc, offsets, lengths, c->mem->buffers_count);
				while(ipaugenblick_socket_kick(fd) != 0);
				chunkqueue_mark_written(cq, c->mem->used);
			}
			break;
		case FILE_CHUNK:
			network_ipaugenblick_file_chunk(srv, con, fd, cq, &max_bytes);
			break;
		}
		c = c->next;
	}	
	return 0;
}
