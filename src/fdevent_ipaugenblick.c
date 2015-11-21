#include "fdevent.h"
#include "buffer.h"
#include "log.h"

static void fdevent_ipaugenblick_free(fdevents *ev) {
	free(ev->ipaugenblick_events);
	ev->ipaugenblick_events = NULL;
}

static int fdevent_ipaugenblick_event_del(fdevents *ev, int fde_ndx, int fd) {

	if (fde_ndx < 0) return -1;

	ipaugenblick_fdclear(fd, &ev->readfdset);
	ipaugenblick_fdclear(fd, &ev->writefdset);
	ipaugenblick_fdclear(fd, &ev->errorfdset);
	return -1;
}

static int fdevent_ipaugenblick_event_set(fdevents *ev, int fde_ndx, int fd, int events) {

	if (fde_ndx != -1) return fd;

	if (events & FDEVENT_IN)  ipaugenblick_fdset(fd, &ev->readfdset);
	if (events & FDEVENT_OUT) ipaugenblick_fdset(fd, &ev->writefdset);

	/**
	 *
	 * with EPOLLET we don't get a FDEVENT_HUP
	 * if the close is delay after everything has
	 * sent.
	 *
	 */

	ipaugenblick_fdset(fd,&ev->errorfdset);

	return fd;
}

static int fdevent_ipaugenblick_poll(fdevents *ev, int timeout_ms) {
	struct timeval timeout;
	timeout.tv_sec = timeout_ms / 1000;
	timeout.tv_usec = timeout_ms * 1000;

	int rc = ipaugenblick_select(ev->epoll_fd,&ev->readfdset,&ev->writefdset,&ev->errorfdset, &timeout);
	if (rc > 0) {
		int event_idx = 0;
		int i;
		if (ev->maxfds < rc)
			ev->ipaugenblick_events = realloc(ev->ipaugenblick_events,ev->maxfds*sizeof(int));
		for(i = 0;i < ev->readfdset.returned_idx;i++) {
			int sock = ipaugenblick_fd_idx2sock(&ev->readfdset,i);
			ev->fdarray[sock]->events = FDEVENT_IN;
			ev->ipaugenblick_events[event_idx++] = sock;
		}
		for(i = 0;i < ev->writefdset.returned_idx;i++) {
			int sock = ipaugenblick_fd_idx2sock(&ev->writefdset,i);
			ev->fdarray[sock]->events |= FDEVENT_OUT;
			ev->ipaugenblick_events[event_idx++] = sock;
		}
		for(i = 0;i < ev->errorfdset.returned_idx;i++) {
			int sock = ipaugenblick_fd_idx2sock(&ev->errorfdset,i);
			ev->fdarray[sock]->events |= FDEVENT_ERR|FDEVENT_HUP;
			ev->ipaugenblick_events[event_idx++] = sock;
		}
	}
	return rc;
}

static int fdevent_ipaugenblick_event_get_revent(fdevents *ev, size_t ndx) {

	return ev->fdarray[ev->ipaugenblick_events[ndx]]->events;
}

static int fdevent_ipaugenblick_event_get_fd(fdevents *ev, size_t ndx) {
# if 0
	log_error_write(ev->srv, __FILE__, __LINE__, "SD, D",
		"fdevent_linux_sysepoll_event_get_fd: ", (int) ndx, ev->epoll_events[ndx].data.fd);
# endif

	return ev->ipaugenblick_events[ndx];
}

static int fdevent_ipaugenblick_event_next_fdndx(fdevents *ev, int ndx) {
	size_t i;

	UNUSED(ev);

	i = (ndx < 0) ? 0 : ndx + 1;

	return i;
}

int fdevent_ipaugenblick_init(fdevents *ev) {
	ev->type = FDEVENT_HANDLER_IPAUGENBLICK;
#define SET(x) \
	ev->x = fdevent_ipaugenblick_##x;

	SET(free);
	SET(poll);

	SET(event_del);
	SET(event_set);

	SET(event_next_fdndx);
	SET(event_get_fd);
	SET(event_get_revent);

	if (-1 == (ev->epoll_fd = ipaugenblick_open_select())) {
		log_error_write(ev->srv, __FILE__, __LINE__, "SSS",
			"ipaugenblick_open_select failed");

		return -1;
	}
	ev->ipaugenblick_events = malloc(ev->maxfds * sizeof(int));
	memset(ev->ipaugenblick_events,0,ev->maxfds * sizeof(int));

	ipaugenblick_fdzero(&ev->readfdset);
	ipaugenblick_fdzero(&ev->writefdset);
	ipaugenblick_fdzero(&ev->errorfdset);
	return 0;
}
