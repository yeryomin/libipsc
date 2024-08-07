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

int ipsc_tls_init( ipsc_t *ipsc, char *cert, char *key, char *ca, char *dhparams )
{
	if ( !ipsc || !cert || !key || !ca || !dhparams )
		return -1;

	int err = 0;
	const SSL_METHOD *m;
	EVP_PKEY *dh = NULL;
	FILE *dhfp = NULL;

	BIO *bio = BIO_new_file( dhparams, "r" );
	if ( !bio )
		return -1;

	dh = PEM_read_bio_Parameters( bio, NULL );
	BIO_free( bio );
	if ( !dh )
		return -1;

	SSL_library_init();

	ipsc->tls = (ipsc_tls_t *)malloc( sizeof(ipsc_tls_t) );
	if ( !ipsc->tls )
		return -1;

	ipsc->tls->data = NULL;
	ipsc->tls->ctx  = NULL;

	if ( ipsc->flags & IPSC_FLAG_SERVER )
		m = TLS_server_method();
	else
		m = TLS_client_method();

	ipsc->tls->ctx = SSL_CTX_new(m);

	if ( !ipsc->tls->ctx )
		return -1;

	/* use tls 1.3 only, with DHE */
	SSL_CTX_set_tmp_dh( ipsc->tls->ctx, dh );
	SSL_CTX_set_min_proto_version( ipsc->tls->ctx, TLS1_3_VERSION );
	SSL_CTX_set_options( ipsc->tls->ctx, SSL_OP_ALL );
	/* TODO: use something else? make it configurable? */
	SSL_CTX_set_cipher_list( ipsc->tls->ctx, "ECDHE-ECDSA-AES128-GCM-SHA256" );

	err = SSL_CTX_use_certificate_file( ipsc->tls->ctx,
					    cert,
					    SSL_FILETYPE_PEM );
	if ( err <= 0 )
		return -1;

	err = SSL_CTX_use_PrivateKey_file( ipsc->tls->ctx,
					   key,
					   SSL_FILETYPE_PEM );
	if ( err <= 0 )
		return -1;

	err = SSL_CTX_check_private_key( ipsc->tls->ctx );
	if ( err != 1 )
		return -1;

	err = SSL_CTX_load_verify_locations( ipsc->tls->ctx, ca, NULL );
	if ( !err )
		return -1;

	SSL_CTX_set_verify( ipsc->tls->ctx, SSL_VERIFY_PEER, NULL );
	SSL_CTX_set_verify_depth( ipsc->tls->ctx, IPSC_MAX_CERT_CHAIN );

	/* TODO: use liba? */
	/* not very good idea in general */
	/* propose patches to openssl to allow passing MSG_NOSIGNAL to send? */
	struct sigaction sa;
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if ( sigaction( SIGPIPE, &sa, 0 ) == -1 )
		return -1;

	ipsc->flags |= IPSC_FLAG_TLS;

	return 0;
}

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
	client->tls     = NULL;

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

int ipsc_accept_tls( ipsc_t *ipsc, ipsc_t *client )
{
	int err = 0;

	client->tls = (ipsc_tls_t *)malloc( sizeof(ipsc_tls_t) );
	if ( !client->tls )
		return -1;

	client->tls->ctx  = NULL;
	client->tls->data = SSL_new( ipsc->tls->ctx );
	if ( !client->tls->data )
		return -1;

	SSL_set_fd( client->tls->data, client->sd );
	SSL_set_accept_state( client->tls->data );
	SSL_do_handshake( client->tls->data );

	ERR_clear_error();
	err = SSL_ERROR_WANT_READ;
	while ( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ) {
		err = SSL_accept( client->tls->data );
		err = SSL_get_error( client->tls->data, err );
	}

	if ( err != SSL_ERROR_NONE )
		return -1;

	client->flags |= IPSC_FLAG_TLS;

	return 0;
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

int ipsc_connect_tls( ipsc_t *ipsc )
{
	int err = 0;

	if ( !ipsc->tls )
		return -1;

	ipsc->tls->data = SSL_new( ipsc->tls->ctx );
	if ( !ipsc->tls->data )
		return -1;

	SSL_set_fd( ipsc->tls->data, ipsc->sd );
	SSL_set_connect_state( ipsc->tls->data );
	SSL_do_handshake( ipsc->tls->data );

	ERR_clear_error();
	err = SSL_ERROR_WANT_READ;
	while ( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ) {
		err = SSL_connect( ipsc->tls->data );
		err = SSL_get_error( ipsc->tls->data, err );
	}

	if ( err != SSL_ERROR_NONE )
		return -1;

	return 0;
}

ssize_t ipsc_send( ipsc_t *ipsc, const void *buf, size_t buflen )
{
	ssize_t sent = 0;
	size_t sent_sum = 0;

	while ( sent_sum < buflen ) {
		if ( ipsc->flags & IPSC_FLAG_TLS )
			sent = SSL_write( ipsc->tls->data,
					  (const char *)buf + sent_sum,
					  buflen - sent_sum );
		else
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
		if ( ipsc->flags & IPSC_FLAG_TLS )
			rb = SSL_read( ipsc->tls->data, (char *)buf + recvd,
							buflen - recvd );
		else
			rb = recv( ipsc->sd, (char *)buf + recvd,
							buflen - recvd, 0 );

		if ( rb < 1 ) {
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
				if ( ipsc->flags & IPSC_FLAG_TLS )
					if ( ipsc_accept_tls( ipsc, client ) ) {
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

	if ( ipsc->flags & IPSC_FLAG_TLS && ipsc->tls->data )
		SSL_shutdown( ipsc->tls->data );

	if ( ipsc->sd > 0 ) {
		shutdown( ipsc->sd, SHUT_RDWR );
		close( ipsc->sd );
	}

	if ( ipsc->flags & IPSC_FLAG_LOCAL && ipsc->flags & IPSC_FLAG_SERVER )
		unlink( ((struct sockaddr_un *)ipsc->addr)->sun_path );

	if ( ipsc->flags & IPSC_FLAG_TLS && ipsc->tls ) {
		SSL_free( ipsc->tls->data );
		SSL_CTX_free( ipsc->tls->ctx );
		ipsc->tls->data = NULL;
		ipsc->tls->ctx = NULL;
		free( ipsc->tls );
		ipsc->tls = NULL;
	}

	free( ipsc->addr );
	free( ipsc );
	ipsc = NULL;
}
