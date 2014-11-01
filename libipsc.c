/**
 * This file is part of libipsc library code.
 *
 * Copyright (C) 2014 Roman Yeryomin <roman@advem.lv>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See LICENCE.txt file for more details.
 */
#include "priv.h"

ipsc_t *ipsc_listen( int st, int proto, char *host, uint16_t port, int maxq )
{
	ipsc_t *ipsc = ipsc_init( st, proto, host, port );
	if ( !ipsc )
		return NULL;

	ipsc->maxq = maxq;
	if ( maxq > IPSC_MAX_QUEUE )
		ipsc->maxq = IPSC_MAX_QUEUE;
	if ( maxq < 1 )
		ipsc->maxq = IPSC_MAX_QUEUE_DEFAULT;

	if ( ipsc_bind( ipsc ) )
		goto exit;

	if ( st == SOCK_STREAM && listen( ipsc->sd, ipsc->maxq ) )
		goto exit;

	ipsc->flags |= IPSC_FLAG_SERVER;

	return ipsc;

exit:
	ipsc_close( ipsc );
	return NULL;
}

ipsc_t *ipsc_accept( ipsc_t *ipsc )
{
	if ( !ipsc )
		return NULL;

	ipsc_t *client = (ipsc_t *)malloc( sizeof(ipsc_t) );
	if ( !client )
		return NULL;

	client->sd      = -1;
	client->maxq    = 0;
	client->flags   = 0;
	client->alen    = ipsc->alen;
	client->addr    = (struct sockaddr *)malloc( client->alen );
	client->cb_args = ipsc->cb_args;

	if ( !client->addr )
		goto exit;

	client->sd = accept( ipsc->sd, client->addr,
			     (socklen_t *)&(client->alen) );
	if ( client->sd > 0 )
		return client;

exit:
	ipsc_close( client );
	return NULL;
}

ipsc_t *ipsc_connect( int st, int proto, char *host, uint16_t port )
{
	ipsc_t *ipsc = ipsc_init( st, proto, host, port );
	if ( !ipsc  )
		return NULL;

	if ( !connect( ipsc->sd, ipsc->addr, ipsc->alen ) )
		return ipsc;

	ipsc_close( ipsc );
	return NULL;
}

ssize_t ipsc_send( ipsc_t *ipsc, const void *buf, size_t buflen )
{
	ssize_t sent = 0;
	size_t sent_sum = 0;

	while ( sent_sum < buflen ) {
		sent = send( ipsc->sd, (const char *)buf + sent_sum,
				buflen - sent_sum, MSG_NOSIGNAL );
		if ( sent == -1 ) {
			if ( errno == EAGAIN ||
			     errno == EWOULDBLOCK ||
			     errno == EINTR )
				continue;
			return sent;
		}
		sent_sum += sent;
	}

	return sent_sum;
}

ssize_t ipsc_recv( ipsc_t *ipsc, void *buf,
		   size_t buflen, unsigned int timeout )
{
	ssize_t rb = 0;
	ssize_t recvd = 0;

	if ( ipsc_set_recv_timeout( ipsc, timeout ) )
		return -1;

	while ( !recvd ) {
		rb = recv( ipsc->sd, (char *)buf + recvd, buflen - recvd, 0 );
		if ( rb == -1 ) {
			if ( ( (errno == EAGAIN || errno == EWOULDBLOCK) &&
						timeout == 0 ) ||
						errno == EINTR )
				continue;
			return rb;
		}
		recvd += rb;
	}

	return recvd;
}

int ipsc_epoll_init( ipsc_t *ipsc )
{
	int epfd;

	if ( ipsc_set_nonblock(ipsc) )
		return -1;

	epfd = epoll_create( ipsc->maxq );
	if ( epfd == -1 )
		return -1;

	if ( ipsc_epoll_newfd( ipsc, epfd ) )
		return -1;

	return epfd;
}

int ipsc_epoll_wait( ipsc_t *ipsc, int epfd, ssize_t (*cb)(ipsc_t *) )
{
	int i;
	int pool = 0;
	ipsc_t *client = NULL;
	struct epoll_event events[ ipsc->maxq ];

	pool = epoll_wait( epfd, events, ipsc->maxq, -1 );
	if ( pool < 0 )
		return -1;

	for ( i = 0; i < pool; i++ ) {
		/* new client connected */
		if ( events[i].data.ptr == ipsc ) {
			/* accept clients, create new fd and add to the pool */
			while ( (client = ipsc_accept(ipsc)) ) {
				if ( ipsc_set_nonblock( client ) ) {
					ipsc_close( client );
					continue;
				}
				if ( ipsc_epoll_newfd( client, epfd ) ) {
					ipsc_close( client );
					continue;
				}
			}
			continue;
		}

		/* explicitly close connection, SCTP fails without this */
		if ( events[i].events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR) ) {
			ipsc_close( events[i].data.ptr );
			continue;
		}

		/* incoming event on previously accepted connection */
		if ( events[i].events & EPOLLIN ) {
			if ( !events[i].data.ptr )
				continue;
			if ( (*cb)( events[i].data.ptr ) < 0 )
				ipsc_close( events[i].data.ptr );
		}
	}

	return 0;
}

void ipsc_close( ipsc_t *ipsc )
{
	if ( !ipsc )
		return;

	if ( ipsc->sd > 0 ) {
		shutdown( ipsc->sd, SHUT_RDWR );
		close( ipsc->sd );
	}

	if ( ipsc->flags & IPSC_FLAG_LOCAL && ipsc->flags & IPSC_FLAG_SERVER )
		unlink( ((struct sockaddr_un *)ipsc->addr)->sun_path );

	free( ipsc->addr );
	free( ipsc );
	ipsc = NULL;
}
