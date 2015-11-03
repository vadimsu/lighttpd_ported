#include "network_backends.h"

#include "network.h"
#include "log.h"

#include "sys-socket.h"

#include <unistd.h>

#include <errno.h>
#include <string.h>
#include <ipaugenblick_api.h>

int network_ipaugenblick_chunkqueue_write(server *srv, connection *con, int fd, chunkqueue *cq, off_t max_bytes) {
	int buffer_count = 0, i;
	chunk* c = cq->first;
	while (max_bytes > 0 && c) {

		switch (cq->first->type) {
		case MEM_CHUNK:
			max_bytes -= c->mem->used;
			buffer_count+=c->mem->buffers_count;
			break;
		case FILE_CHUNK:
		//TODO	r = network_write_file_chunk_mmap(srv, con, fd, cq, &max_bytes);
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
