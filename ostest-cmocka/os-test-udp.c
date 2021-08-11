/*  gcc os-test-udp.c -o os-test -I/usr/local/include -L/usr/local/lib -lcmocka */

#ifdef __HAIKU__
#define _BSD_SOURCE
#endif

#include <sys/socket.h>

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__minix__)
#include <sys/endian.h>
#elif defined(__APPLE__)
#define htobe16 htons
#define htobe32 htonl
#else
#include <endian.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Address to send packets too that do not send back any ICMP connection refused
// packets.
#define BLACKHOLE_HOST 0x08080808
#define BLACKHOLE_PORT 53

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

/* Test that a socket being non-blocking has no effect on accept failing with
   ENOTSUP. */
static void ostest_accept_nonblock(void **state) {
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		fail_msg("socket");
	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
		fail_msg("fcntl");
	if (accept(fd, NULL, NULL) < 0)
		fail_msg("accept");
}

/* Test if accept on UDP socket is rejected with ENOTSUP. */
static void ostest_accept(void **state) {
    (void) state;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		fail_msg("socket");
	if (accept(fd, NULL, NULL) < 0)
		fail_msg("accept");
}

/* Test what the remote address is after binding to the any address port 0. */
static void ostest_bind_any_0_getpeername(void **state) {
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if (bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0)
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if (getpeername(fd, (struct sockaddr*) &local, &locallen) < 0)
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "%s:%s\n", port, port);
}

/* Test what the local address is after binding to the any address port 0. */
static void ostest_bind_any_0_getsockname(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(0);
	if (bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0)
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if (getsockname(fd, (struct sockaddr*) &local, &locallen) < 0)
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if (!strncmp(host, "192.168.", strlen("192.168.")))
		fprintf(stderr, "192.168.1.x");
	else if (!strncmp(host, "100.82.", strlen("100.82.")))
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	putchar(':');
	if (!strcmp(port, "0"))
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Bind to the any address port 0 and test if binding to AF_UNSPEC unbinds the
   socket. */
static void ostest_bind_any_0_unbind(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(0);
	if (bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0)
		fail_msg("bind");
	struct sockaddr_in cos;
	memset(&cos, 0, sizeof(cos));
	cos.sin_family = AF_UNSPEC;
	if (bind(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0)
		fail_msg("bind AF_UNSPEC");
}

/* Test that it works to bind to the any address with port 0. */
static void ostest_bind_any_0(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(0);
	if (bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0)
		fail_msg("first bind");
}

/* Test binding to the broadcast address port 0 and print the remote address. */
static void ostest_bind_broadcast_0_getpeername(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	sin.sin_port = htobe16(0);
	if (bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0)
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if (getpeername(fd, (struct sockaddr*) &local, &locallen) < 0)
		fail_msg("getpeername");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "%s:%s\n", port, port);
}

/* Test binding to the broadcast address port 0 and print the local address. */
static void ostest_bind_broadcast_0_getsockname(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	sin.sin_port = htobe16(0);
	if (bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0)
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if (getsockname(fd, (struct sockaddr*) &local, &locallen) < 0)
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if (!strncmp(host, "192.168.", strlen("192.168.")))
		fprintf(stderr, "192.168.1.x");
	else if (!strncmp(host, "100.82.", strlen("100.82.")))
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	putchar(':');
	if (!strcmp(port, "0"))
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Test whether binding to the same port on the any address and any address will
    conflict when SO_REUSEADDR is passed on both sockets. */
static void ostest_bind_conflict_any_any_so_reuseaddr_both(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd1 < 0)
		fail_msg("first socket");
	int enable = 1;
	if (setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
		fail_msg("first setsockopt: SO_REUSEADDR");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(0);
	if (bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0)
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if (getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0)
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_ANY);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd2 < 0)
		fail_msg("second socket");
	if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
		fail_msg("second setsockopt: SO_REUSEADDR");
	if (bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0)
		fail_msg("second bind");
}

/* Test whether binding to the same port on the any address and any address will
    conflict when SO_REUSEADDR is passed on the second socket. */
static void ostest_bind_conflict_any_any_so_reuseaddr(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd1 < 0)
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(0);
	if (bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0)
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if (getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0)
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_ANY);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd2 < 0)
		fail_msg("second socket");
	int enable = 1;
	if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
		fail_msg("setsockopt: SO_REUSEADDR");
	if (bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0)
		fail_msg("second bind");
}

/* Test whether binding to the same port on the any address and any address will
    conflict. */
static void ostest_bind_conflict_any_any(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd1 < 0)
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(0);
	if (bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0)
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if (getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0)
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_ANY);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd2 < 0)
		fail_msg("second socket");
	if (bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0)
		fail_msg("second bind");
}

/* Test whether binding to the same port on the any address and broadcast
   address will conflict when SO_REUSEADDR is passed on both sockets. */
static void ostest_bind_conflict_any_broadcast_so_reuseaddr_both(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	int enable = 1;
	if ( setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("first setsockopt: SO_REUSEADDR");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("second setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the any address and broadcast
   address will conflict when SO_REUSEADDR is passed on the second socket. */
static void ostest_bind_conflict_any_broadcast_so_reuseaddr(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	int enable = 1;
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the any address and broadcast
   address will conflict. */
static void ostest_bind_conflict_any_broadcast(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the any address and loopback
   address will conflict when SO_REUSEADDR is passed on both sockets. */
static void ostest_bind_conflict_any_loopback_so_reuseaddr_both(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	int enable = 1;
	if ( setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("first setsockopt: SO_REUSEADDR");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("second setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the any address and loopback
   address will conflict when SO_REUSEADDR is passed on the second socket. */
static void ostest_bind_conflict_any_loopback_so_reuseaddr(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	int enable = 1;
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the any address and loopback
   address will conflict. */
static void ostest_bind_conflict_any_loopback(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the broadcast address and any
   address will conflict when SO_REUSEADDR is passed on both sockets. */
static void ostest_bind_conflict_broadcast_any_so_reuseaddr_both(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	int enable = 1;
	if ( setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("first setsockopt: SO_REUSEADDR");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_ANY);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("second setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the broadcast address and any
   address will conflict when SO_REUSEADDR is passed on the second socket. */
static void ostest_bind_conflict_broadcast_any_so_reuseaddr(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_ANY);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	int enable = 1;
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the broadcast address and any
   address will conflict. */
static void ostest_bind_conflict_broadcast_any(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_ANY);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}


/* Test whether binding to the same port on the broadcast address and broadcast
   address will conflict when SO_REUSEADDR is passed on both sockets. */
static void ostest_bind_conflict_broadcast_broadcast_so_reuseaddr_both(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	int enable = 1;
	if ( setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("first setsockopt: SO_REUSEADDR");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("second setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the broadcast address and broadcast
   address will conflict when SO_REUSEADDR is passed on the second socket. */
static void ostest_bind_conflict_broadcast_broadcast_so_reuseaddr(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	int enable = 1;
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}


/* Test whether binding to the same port on the broadcast address and broadcast
   address will conflict. */
static void ostest_bind_conflict_broadcast_broadcast(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the broadcast address and loopback
   address will conflict when SO_REUSEADDR is passed on both sockets. */
static void ostest_bind_conflict_broadcast_loopback_so_reuseaddr_both(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	int enable = 1;
	if ( setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("first setsockopt: SO_REUSEADDR");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("second setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the broadcast address and loopback
   address will conflict when SO_REUSEADDR is passed on the second socket. */
static void ostest_bind_conflict_broadcast_loopback_so_reuseaddr(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	int enable = 1;
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}


/* Test whether binding to the same port on the broadcast address and loopback
   address will conflict. */
static void ostest_bind_conflict_broadcast_loopback(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the loopback address and any address
   will conflict when SO_REUSEADDR is passed on both sockets. */
static void ostest_bind_conflict_loopback_any_so_reuseaddr_both(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	int enable = 1;
	if ( setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("first setsockopt: SO_REUSEADDR");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_ANY);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("second setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the loopback address and any address
   will conflict when SO_REUSEADDR is passed on the second socket. */
static void ostest_bind_conflict_loopback_any_so_reuseaddr(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_ANY);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	int enable = 1;
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the loopback address and any address
   will conflict. */
static void ostest_bind_conflict_loopback_any(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_ANY);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the loopback address and broadcast
   address will conflict when SO_REUSEADDR is passed on both sockets. */
static void ostest_bind_conflict_loopback_broadcast_so_reuseaddr_both(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	int enable = 1;
	if ( setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("first setsockopt: SO_REUSEADDR");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("second setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the loopback address and broadcast
   address will conflict when SO_REUSEADDR is passed on the second socket. */
static void ostest_bind_conflict_loopback_broadcast_so_reuseaddr(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	int enable = 1;
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the loopback address and broadcast
   address will conflict. */
static void ostest_bind_conflict_loopback_broadcast(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the loopback address and loopback
   address will conflict when SO_REUSEADDR is passed on both sockets. */
static void ostest_bind_conflict_loopback_loopback_so_reuseaddr_both(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	int enable = 1;
	if ( setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("setsockopt: SO_REUSEADDR");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("second setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the loopback address and loopback
   address will conflict when SO_REUSEADDR is passed on the second socket. */
static void ostest_bind_conflict_loopback_loopback_so_reuseaddr(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	int enable = 1;
	if ( setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0 )
		fail_msg("setsockopt: SO_REUSEADDR");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test whether binding to the same port on the loopback address and loopback
   address will conflict. */
static void ostest_bind_conflict_loopback_loopback(void **state)
{
    (void) state;
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in cos;
	socklen_t coslen = sizeof(cos);
	if ( getsockname(fd1, (struct sockaddr*) &cos, &coslen) < 0 )
		fail_msg("getsockname");
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second bind");
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, send a datagram to the same socket, and then test the
   poll status bits on the socket. */
static void ostest_bind_connect_self_send_poll(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	printf("0");
	if ( pfd.revents & POLLIN )
		printf(" | POLLIN");
	if ( pfd.revents & POLLPRI )
		printf(" | POLLPRI");
	if ( pfd.revents & POLLOUT )
		printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		printf(" | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		printf(" | POLLERR");
	if ( pfd.revents & POLLHUP )
		printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		printf(" | POLLWRBAND");
#endif
	putchar('\n');
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, send a datagram to the same socket, and then test if the
   datagram can be received. */
static void ostest_bind_connect_self_send_recv(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		printf("recv %zi bytes\n", amount);
	else if ( x != 'x' )
		printf("recv wrong byte");
	else
		printf("%c\n", x);
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, send a datagram, shutdown for reading,
   and then test the poll bits set. */
static void ostest_bind_connect_self_send_shutdown_r_poll(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	if ( connect(fd, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_RD) )
		fail_msg("shutdown");
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	printf("0");
	if ( pfd.revents & POLLIN )
		printf(" | POLLIN");
	if ( pfd.revents & POLLPRI )
		printf(" | POLLPRI");
	if ( pfd.revents & POLLOUT )
		printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		printf(" | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		printf(" | POLLERR");
	if ( pfd.revents & POLLHUP )
		printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		printf(" | POLLWRBAND");
#endif
	putchar('\n');
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, send a datagram, shutdown for reading,
   receive a datagram, and then test receiving another datagram. */
static void ostest_bind_connect_self_send_shutdown_r_recv_recv(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	if ( connect(fd, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_RD) )
		fail_msg("shutdown");
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("first recv");
	else if ( amount == 0 )
		fail_msg("first recv: EOF");
	else if ( amount != 1 )
		fail_msg("first recv: %zi bytes\n", amount);
	else if ( x != 'x' )
		fail_msg("first recv: wrong byte");
	else
		printf("first recv: %c\n", x);
	fflush(stdout);
	amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("second recv");
	else if ( amount == 0 )
		fail_msg("second recv: EOF");
	else if ( amount != 1 )
		fail_msg("second recv: %zi bytes\n", amount);
	else if ( x != 'x' )
		fail_msg("second recv: wrong byte");
	else
		printf("second recv: %c\n", x);
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, send a datagram, shutdown for reading,
   and then test receiving a datagram. */
static void ostest_bind_connect_self_send_shutdown_r_recv(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	if ( connect(fd, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_RD) )
		fail_msg("shutdown");
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		printf("recv %zi bytes\n", amount);
	else if ( x != 'x' )
		printf("recv wrong byte");
	else
		printf("%c\n", x);
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, send a datagram, shutdown for reading
   and writing, and then test the poll bits set. */
static void ostest_bind_connect_self_send_shutdown_rw_poll(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	if ( connect(fd, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	printf("0");
	if ( pfd.revents & POLLIN )
		printf(" | POLLIN");
	if ( pfd.revents & POLLPRI )
		printf(" | POLLPRI");
	if ( pfd.revents & POLLOUT )
		printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		printf(" | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		printf(" | POLLERR");
	if ( pfd.revents & POLLHUP )
		printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		printf(" | POLLWRBAND");
#endif
	putchar('\n');
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, send a datagram, shutdown for reading
   and writing, receive a datagram, and then test receiving another datagram. */
static void ostest_bind_connect_self_send_shutdown_rw_recv_recv(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	if ( connect(fd, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("first recv");
	else if ( amount == 0 )
		fail_msg("first recv: EOF");
	else if ( amount != 1 )
		fail_msg("first recv: %zi bytes\n", amount);
	else if ( x != 'x' )
		fail_msg("first recv: wrong byte");
	else
		printf("first recv: %c\n", x);
	fflush(stdout);
	amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("second recv");
	else if ( amount == 0 )
		fail_msg("second recv: EOF");
	else if ( amount != 1 )
		fail_msg("second recv: %zi bytes\n", amount);
	else if ( x != 'x' )
		fail_msg("second recv: wrong byte");
	else
		printf("second recv: %c\n", x);
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, send a datagram, shutdown for reading
   and writing, and then test receiving a datagram. */
static void ostest_bind_connect_self_send_shutdown_rw_recv(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	if ( connect(fd, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		printf("recv %zi bytes\n", amount);
	else if ( x != 'x' )
		printf("recv wrong byte");
	else
		printf("%c\n", x);
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, and then test if a datagram can be send to the socket's
   own address. */

static void ostest_bind_connect_self_send(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, shutdown for reading, and then send a
   datagram to itself. */
static void ostest_bind_connect_self_shutdown_r_send_poll(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	if ( connect(fd, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("connect");
	if ( shutdown(fd, SHUT_RD) )
		fail_msg("shutdown");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	printf("0");
	if ( pfd.revents & POLLIN )
		printf(" | POLLIN");
	if ( pfd.revents & POLLPRI )
		printf(" | POLLPRI");
	if ( pfd.revents & POLLOUT )
		printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		printf(" | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		printf(" | POLLERR");
	if ( pfd.revents & POLLHUP )
		printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		printf(" | POLLWRBAND");
#endif
	putchar('\n');
}


/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, shutdown for reading, send a datagram
   to itself, and then test receiving a datagram. */
static void ostest_bind_connect_self_shutdown_r_send_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	if ( connect(fd, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("connect");
	if ( shutdown(fd, SHUT_RD) )
		fail_msg("shutdown");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		printf("recv %zi bytes\n", amount);
	else if ( x != 'x' )
		printf("recv wrong byte");
	else
		printf("%c\n", x);
}


/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, and then test if it can be connected to. */
static void ostest_bind_connect_self(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	if ( connect(fd, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("connect");
}

/* Test binding to the broadcast address in the lan subnet. */
static void ostest_bind_lan_subnet_broadcast(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(BLACKHOLE_HOST);
	sin.sin_port = htobe16(BLACKHOLE_PORT);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	in_addr_t address = ntohl(local.sin_addr.s_addr);
	in_addr_t subnetmask = 0;
	if ( (address & 0xFF000000) == 0x0A000000 )
		subnetmask = 0xFFFFF000; // /20
	else if ( (address & 0xFFF00000) == 0xAC100000 )
		subnetmask = 0xFFF00000; // /12
	else if ( (address & 0xFFFF0000) == 0xC0A80000 )
		subnetmask = 0xFFFFFF00; // /24
	else if ( (address & 0xFFFF8000) == 0x64528000 )
		subnetmask = 0xFFFF8000; // /17
	else
		fail_msg("couldn't deduce local area subnet of: %u.%u.%u.%u",
		     address >> 24 & 0xFF, address >> 16 & 0xFF,
		     address >>  8 & 0xFF, address >>  0 & 0xFF);
	in_addr_t target_address = address | ~subnetmask;
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	struct sockaddr_in cos;
	memset(&sin, 0, sizeof(sin));
	cos.sin_family = AF_INET;
	cos.sin_addr.s_addr = htonl(target_address);
	cos.sin_port = htobe16(0);
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("bind");
}

/* Test binding to the first address in the lan subnet. */
static void ostest_bind_lan_subnet_first(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(BLACKHOLE_HOST);
	sin.sin_port = htobe16(BLACKHOLE_PORT);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	in_addr_t address = ntohl(local.sin_addr.s_addr);
	in_addr_t subnetmask = 0;
	if ( (address & 0xFF000000) == 0x0A000000 )
		subnetmask = 0xFFFFF000; // /20
	else if ( (address & 0xFFF00000) == 0xAC100000 )
		subnetmask = 0xFFF00000; // /12
	else if ( (address & 0xFFFF0000) == 0xC0A80000 )
		subnetmask = 0xFFFFFF00; // /24
	else if ( (address & 0xFFFF8000) == 0x64528000 )
		subnetmask = 0xFFFF8000; // /17
	else
		fail_msg("couldn't deduce local area subnet of: %u.%u.%u.%u",
		     address >> 24 & 0xFF, address >> 16 & 0xFF,
		     address >>  8 & 0xFF, address >>  0 & 0xFF);
	in_addr_t target_address = address & subnetmask;
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	struct sockaddr_in cos;
	memset(&sin, 0, sizeof(sin));
	cos.sin_family = AF_INET;
	cos.sin_addr.s_addr = htonl(target_address);
	cos.sin_port = htobe16(0);
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("bind");
}

/* Test binding to a wrong address (neither the first address, the local
   address, nor the last/broadcast address) in the lan subnet. */
static void ostest_bind_lan_subnet_wrong(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(BLACKHOLE_HOST);
	sin.sin_port = htobe16(BLACKHOLE_PORT);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	in_addr_t address = ntohl(local.sin_addr.s_addr);
	in_addr_t subnetmask = 0;
	if ( (address & 0xFF000000) == 0x0A000000 )
		subnetmask = 0xFFFFF000; // /20
	else if ( (address & 0xFFF00000) == 0xAC100000 )
		subnetmask = 0xFFF00000; // /12
	else if ( (address & 0xFFFF0000) == 0xC0A80000 )
		subnetmask = 0xFFFFFF00; // /24
	else if ( (address & 0xFFFF8000) == 0x64528000 )
		subnetmask = 0xFFFF8000; // /17
	else
		fail_msg("couldn't deduce local area subnet of: %u.%u.%u.%u",
		     address >> 24 & 0xFF, address >> 16 & 0xFF,
		     address >>  8 & 0xFF, address >>  0 & 0xFF);
	in_addr_t target_address = (address & subnetmask) + 1;
	if ( target_address == address )
		target_address = (address & subnetmask) + 2;
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	struct sockaddr_in cos;
	memset(&sin, 0, sizeof(sin));
	cos.sin_family = AF_INET;
	cos.sin_addr.s_addr = htonl(target_address);
	cos.sin_port = htobe16(0);
	if ( bind(fd2, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("bind");
}

/* Bind to loopback address port 0 and print the remote address. */
static void ostest_bind_loopback_0_getpeername(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getpeername(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	printf("%s:%s\n", port, port);
}

/* Bind to loopback address port 0 and print the local address. */
static void ostest_bind_loopback_0_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		printf("192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		printf("192.168.1.x");
	else
		printf("%s", host);
	putchar(':');
	if ( !strcmp(port, "0") )
		printf("%s", port);
	else
		printf("non-zero");
	printf("\n");
}

/* Test binding to the loopback network broadcast address. */
static void ostest_bind_loopback_broadcast(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(0x7fffffff); /* 127.255.255.255 */
	sin.sin_port = 0;
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
}

/* Test binding to another address in the loopback network. */
static void ostest_bind_loopback_other(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(0x7f000002); /* 127.0.0.2 */
	sin.sin_port = 0;
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
}

/* Test if a socket can be bound twice. */
static void ostest_bind_rebind(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
}

/* Bind to loopback port 0, send a datagram to the same socket, and then
   test receiving a datagram. */
static void ostest_bind_sendto_self_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		printf("recv %zi bytes\n", amount);
	else if ( x != 'x' )
		printf("recv wrong byte");
	else
		printf("%c\n", x);
}

/* Bind to loopback port 0 and test sending a datagram to the same socket. */
static void ostest_bind_sendto_self(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
}

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, then test the poll bits on the first socket. */
static void ostest_bind_socket_sendto_first_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("socket");
	char x = 'x';
	if ( sendto(fd2, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	printf("0");
	if ( pfd.revents & POLLIN )
		printf(" | POLLIN");
	if ( pfd.revents & POLLPRI )
		printf(" | POLLPRI");
	if ( pfd.revents & POLLOUT )
		printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		printf(" | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		printf(" | POLLERR");
	if ( pfd.revents & POLLHUP )
		printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		printf(" | POLLWRBAND");
#endif
	putchar('\n');
}

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, then test receiving a datagram on the first
   socket. */
static void ostest_bind_socket_sendto_first_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("socket");
	char x = 'x';
	if ( sendto(fd2, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		printf("recv %zi bytes\n", amount);
	else if ( x != 'x' )
		printf("recv wrong byte");
	else
		printf("%c\n", x);
}

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, shutdown the first socket for reading, and
   then test the poll bits on the first socket. */
static void ostest_bind_socket_sendto_first_shutdown_r_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("socket");
	char x = 'x';
	if ( sendto(fd2, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	if ( shutdown(fd, SHUT_RD) < 0 )
		fail_msg("shutdown");
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	printf("0");
	if ( pfd.revents & POLLIN )
		printf(" | POLLIN");
	if ( pfd.revents & POLLPRI )
		printf(" | POLLPRI");
	if ( pfd.revents & POLLOUT )
		printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		printf(" | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		printf(" | POLLERR");
	if ( pfd.revents & POLLHUP )
		printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		printf(" | POLLWRBAND");
#endif
	putchar('\n');
}

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, shutdown the first socket for reading, and
   then test receiving a datagram on the first socket. */
static void ostest_bind_socket_sendto_first_shutdown_r_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("socket");
	char x = 'x';
	if ( sendto(fd2, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	if ( shutdown(fd, SHUT_RD) < 0 )
		fail_msg("shutdown");
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		printf("recv %zi bytes\n", amount);
	else if ( x != 'x' )
		printf("recv wrong byte");
	else
		printf("%c\n", x);
}

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, shutdown the first socket for reading and
   writing, and then test the poll bits on the first socket. */
static void ostest_bind_socket_sendto_first_shutdown_rw_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("socket");
	char x = 'x';
	if ( sendto(fd2, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	if ( shutdown(fd, SHUT_RDWR) < 0 )
		fail_msg("shutdown");
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	printf("0");
	if ( pfd.revents & POLLIN )
		printf(" | POLLIN");
	if ( pfd.revents & POLLPRI )
		printf(" | POLLPRI");
	if ( pfd.revents & POLLOUT )
		printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		printf(" | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		printf(" | POLLERR");
	if ( pfd.revents & POLLHUP )
		printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		printf(" | POLLWRBAND");
#endif
	putchar('\n');
}

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, shutdown the first socket for reading and
   writing, and then test receiving a datagram on the first socket. */
static void ostest_bind_socket_sendto_first_shutdown_rw_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("socket");
	char x = 'x';
	if ( sendto(fd2, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	if ( shutdown(fd, SHUT_RDWR) < 0 )
		fail_msg("shutdown");
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		printf("recv %zi bytes\n", amount);
	else if ( x != 'x' )
		printf("recv wrong byte");
	else
		printf("%c\n", x);
}

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, shutdown the first socket for writing, and
   then test the poll bits on the first socket. */
static void ostest_bind_socket_sendto_first_shutdown_w_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("socket");
	char x = 'x';
	if ( sendto(fd2, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	if ( shutdown(fd, SHUT_WR) < 0 )
		fail_msg("shutdown");
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	printf("0");
	if ( pfd.revents & POLLIN )
		printf(" | POLLIN");
	if ( pfd.revents & POLLPRI )
		printf(" | POLLPRI");
	if ( pfd.revents & POLLOUT )
		printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		printf(" | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		printf(" | POLLERR");
	if ( pfd.revents & POLLHUP )
		printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		printf(" | POLLWRBAND");
#endif
	putchar('\n');
}

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, shutdown the first socket for writing, and
   then test receiving a datagram on the first socket. */
static void ostest_bind_socket_sendto_first_shutdown_w_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("socket");
	char x = 'x';
	if ( sendto(fd2, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	if ( shutdown(fd, SHUT_WR) < 0 )
		fail_msg("shutdown");
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		printf("recv %zi bytes\n", amount);
	else if ( x != 'x' )
		printf("recv wrong byte");
	else
		printf("%c\n", x);
}

/* Bind to loopback port 0, make another socket, shutdown the first socket for
   reading, send a datagram from the second socket to the first socket, and
   then test the poll bits on the first socket. */
static void ostest_bind_socket_shutdown_r_sendto_first_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("socket");
	if ( shutdown(fd, SHUT_RD) < 0 )
		fail_msg("shutdown");
	char x = 'x';
	if ( sendto(fd2, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	printf("0");
	if ( pfd.revents & POLLIN )
		printf(" | POLLIN");
	if ( pfd.revents & POLLPRI )
		printf(" | POLLPRI");
	if ( pfd.revents & POLLOUT )
		printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		printf(" | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		printf(" | POLLERR");
	if ( pfd.revents & POLLHUP )
		printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		printf(" | POLLWRBAND");
#endif
	putchar('\n');
}

/* Bind to loopback port 0, make another socket, shutdown the first socket for
   reading, send a datagram from the second socket to the first socket, and
   then test receiving a datagram on the first socket. */
static void ostest_bind_socket_shutdown_r_sendto_first_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("socket");
	if ( shutdown(fd, SHUT_RD) < 0 )
		fail_msg("shutdown");
	char x = 'x';
	if ( sendto(fd2, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		printf("recv %zi bytes\n", amount);
	else if ( x != 'x' )
		printf("recv wrong byte");
	else
		printf("%c\n", x);
}

/* Bind to loopback port 0, make another socket, shutdown the first socket for
   reading and writing, send a datagram from the second socket to the first
   socket, and then test the poll bits on the first socket. */
static void ostest_bind_socket_shutdown_rw_sendto_first_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("socket");
	if ( shutdown(fd, SHUT_RDWR) < 0 )
		fail_msg("shutdown");
	char x = 'x';
	if ( sendto(fd2, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	printf("0");
	if ( pfd.revents & POLLIN )
		printf(" | POLLIN");
	if ( pfd.revents & POLLPRI )
		printf(" | POLLPRI");
	if ( pfd.revents & POLLOUT )
		printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		printf(" | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		printf(" | POLLERR");
	if ( pfd.revents & POLLHUP )
		printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		printf(" | POLLWRBAND");
#endif
	putchar('\n');
}

/* Bind to loopback port 0, make another socket, shutdown the first socket for
   reading and writing, send a datagram from the second socket to the first
   socket, and then test receiving a datagram on the first socket. */
static void ostest_bind_socket_shutdown_rw_sendto_first_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("socket");
	if ( shutdown(fd, SHUT_RDWR) < 0 )
		fail_msg("shutdown");
	char x = 'x';
	if ( sendto(fd2, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		printf("recv %zi bytes\n", amount);
	else if ( x != 'x' )
		printf("recv wrong byte");
	else
		printf("%c\n", x);
}

/* Bind to loopback port 0, make another socket, shutdown the first socket for
   writing, send a datagram from the second socket to the first socket, and
   then test the poll bits on the first socket. */
static void ostest_bind_socket_shutdown_w_sendto_first_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("socket");
	if ( shutdown(fd, SHUT_WR) < 0 )
		fail_msg("shutdown");
	char x = 'x';
	if ( sendto(fd2, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	printf("0");
	if ( pfd.revents & POLLIN )
		printf(" | POLLIN");
	if ( pfd.revents & POLLPRI )
		printf(" | POLLPRI");
	if ( pfd.revents & POLLOUT )
		printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		printf(" | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		printf(" | POLLERR");
	if ( pfd.revents & POLLHUP )
		printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		printf(" | POLLWRBAND");
#endif
	putchar('\n');
}

/* Bind to loopback port 0, make another socket, shutdown the first socket for
   writing, send a datagram from the second socket to the first socket, and
   then test receiving a datagram on the first socket. */
static void ostest_bind_socket_shutdown_w_sendto_first_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("socket");
	if ( shutdown(fd, SHUT_WR) < 0 )
		fail_msg("shutdown");
	char x = 'x';
	if ( sendto(fd2, &x, sizeof(x), 0,
	            (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("sendto");
	usleep(50000);
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		printf("recv %zi bytes\n", amount);
	else if ( x != 'x' )
		printf("recv wrong byte");
	else
		printf("%c\n", x);
}

/* Test connecting to the any address port 0 and printing the remote address. */
static void ostest_connect_any_0_getpeername(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(0);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getpeername(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getpeername");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "%s:%s\n", host, port);
}

/* Test connecting to the any address port 0 and printing the local address. */
static void ostest_connect_any_0_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(0);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Test connecting to the any address port 65535 and printing the remote
   address. */
static void ostest_connect_any_getpeername(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getpeername(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getpeername");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "%s:%s\n", host, port);
}

/* Test connecting to the any address port 65535 and printing the local
   address. */
static void ostest_connect_any_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Test setting SO_BROADCAST, connecting to the broadcast address port 1 and
   printing the remote address. */
static void ostest_connect_broadcast_getpeername_so_broadcast(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	int enable = 1;
	if ( setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) < 0 )
		fail_msg("setsockopt: SO_BROADCAST");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	sin.sin_port = htobe16(1);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getpeername(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getpeername");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "%s:%s\n", host, port);
}

/* Test connecting to the broadcast address port 1 and printing the remote
   address. */
static void ostest_connect_broadcast_getpeername(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	sin.sin_port = htobe16(1);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getpeername(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getpeername");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "%s:%s\n", host, port);
}

/* Test setting SO_BROADCAST, connecting to the broadcast address port 1 and
   printing the local address. */
static void ostest_connect_broadcast_getsockname_so_broadcast(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	int enable = 1;
	if ( setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) < 0 )
		fail_msg("setsockopt: SO_BROADCAST");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	sin.sin_port = htobe16(1);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Test connecting to the broadcast address port 1 and printing the local
   address. */
static void ostest_connect_broadcast_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_BROADCAST);
	sin.sin_port = htobe16(1);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Test connecting to the any address port 0 and printing the local address. */
static void ostest_connect_getpeername(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getpeername(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getpeername");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "%s:%s\n", host, port);
}

/* Connect to the loopback interface port 0 and print the remote address. */
static void ostest_connect_loopback_0_getpeername(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getpeername(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getpeername");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "%s:%s\n", host, port);
}

/* Connect to the loopback interface port 0 and print the local address. */
static void ostest_connect_loopback_0_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Connect to the loopback address port 65535 and test if the socket was bound
   to an interface according to SO_BINDTODEVICE. */
static void ostest_connect_loopback_get_so_bindtodevice(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
#ifdef SO_BINDTODEVICE
	char ifname[IF_NAMESIZE + 1];
	socklen_t ifnamelen = sizeof(ifname);
	if ( getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, &ifnamelen) < 0 )
		fail_msg("getsockopt: SO_BINDTODEVICE");
	ifname[ifnamelen] = '\0';
	puts(ifname);
#else
	errno = ENOSYS;
	fail_msg("getsockopt: SO_BINDTODEVICE");
#endif
}

/* Connect to the loopback interface port 65535 and print the remote address. */
static void ostest_connect_loopback_getpeername(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getpeername(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getpeername");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "%s:%s\n", host, port);
}

/* Connect to the loopback interface port 65535 and print the local address. */
static void ostest_connect_loopback_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Connect to the loopback address port 65535, and then test reconnecting to the
   loopback address port 65534 and print the local address. */
static void ostest_connect_loopback_reconnect_loopback_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	struct sockaddr_in cos;
	memset(&sin, 0, sizeof(cos));
	cos.sin_family = AF_INET;
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	cos.sin_port = htobe16(65534);
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("second getsockname");
	char second_port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            second_port, sizeof(second_port),
	            NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, second_port) )
		fprintf(stderr, "same port");
	else
		fprintf(stderr, "%s", second_port);
	fprintf(stderr, "\n");
}

/* Connect to the loopback address port 65535, and then test reconnecting to the
   public internet and print the local address. */
static void ostest_connect_loopback_reconnect_wan_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	struct sockaddr_in cos;
	memset(&sin, 0, sizeof(cos));
	cos.sin_family = AF_INET;
	cos.sin_addr.s_addr = htobe32(BLACKHOLE_HOST);
	cos.sin_port = htobe16(BLACKHOLE_PORT);
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("second getsockname");
	char second_port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            second_port, sizeof(second_port),
	            NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, second_port) )
		fprintf(stderr, "same port");
	else
		fprintf(stderr, "%s", second_port);
	fprintf(stderr, "\n");
}

/* Connect to the loopback address port 65535, then unconnect, and test binding
   to the any address port 0, and then print the local address. */
static void ostest_connect_loopback_unconnect_rebind_any_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	struct sockaddr_in foo;
	memset(&foo, 0, sizeof(foo));
	foo.sin_family = AF_INET;
	foo.sin_addr.s_addr = htobe32(INADDR_ANY);
	foo.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &foo, sizeof(foo)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Connect to the loopback address port 65535, then unconnect, and test binding
   to the loopback address port 0, and then print the local address. */
static void ostest_connect_loopback_unconnect_rebind_loopback_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	struct sockaddr_in foo;
	memset(&foo, 0, sizeof(foo));
	foo.sin_family = AF_INET;
	foo.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	foo.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &foo, sizeof(foo)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Connect to loopback address port 65535 and then test the poll bits. */
static void ostest_connect_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Connect to the loopback address port 65535, then test reconnecting to the any
   address port 0 and print the local address. */
static void ostest_connect_reconnect_any_getpeername(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr_in cos;
	memset(&cos, 0, sizeof(cos));
	cos.sin_family = AF_INET;
	cos.sin_addr.s_addr = htobe32(INADDR_ANY);
	cos.sin_port = htobe16(0);
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getpeername(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getpeername");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "%s:%s\n", host, port);
}

/* Connect to loopback address port 65535, reconnect to the loopback address
   port 65534, and then print the local address. */
static void ostest_connect_reconnect_getpeername(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr_in cos;
	memset(&cos, 0, sizeof(cos));
	cos.sin_family = AF_INET;
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	cos.sin_port = htobe16(65534);
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getpeername(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getpeername");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "%s:%s\n", host, port);
}

/* Connect to the loopback interface port 65535 and then test reconnecting to
   the same address. */
static void ostest_connect_reconnect_same(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second connect");
}

/* Connect to loopback address port 65535 and then test reconnecting to the
   loopback address port 65534. */
static void ostest_connect_reconnect(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr_in cos;
	memset(&cos, 0, sizeof(cos));
	cos.sin_family = AF_INET;
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	cos.sin_port = htobe16(65534);
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
}

/* Connect to the loopback address port 65535 and then test receiving a
   datagram. */
static void ostest_connect_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x;
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	if ( amount == 0 )
		puts("EOF");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, and then test if accept delivers the asynchronous
   error. */
static void ostest_connect_send_error_accept(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("send");
	usleep(50000);
	if ( accept(fd, NULL, NULL) < 0 )
		fail_msg("accept");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, and then test if getpeername delivers the
   asynchronous error. */
static void ostest_connect_send_error_getpeername(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("send");
	usleep(50000);
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getpeername(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getpeername");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, and then test if getsockname delivers the
   asynchronous error. */
static void ostest_connect_send_error_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("send");
	usleep(50000);
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, and then test if listen delivers the asynchronous
   error. */
static void ostest_connect_send_error_listen(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("send");
	usleep(50000);
	if ( listen(fd, 1) < 0 )
		fail_msg("listen");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, and then test if the poll bits change if poll is
   run twice. */
static void ostest_connect_send_error_poll_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("send");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("first poll");
	if ( num_events == 0 )
		fail_msg("first poll returned 0");
	fprintf(stderr, "first poll: 0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("second poll");
	if ( num_events == 0 )
		fail_msg("second poll returned 0");
	fprintf(stderr, "second poll: 0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, get error with SO_ERROR, and then test the poll
   bits. */
static void ostest_connect_send_error_poll_so_error_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("send");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("first poll");
	if ( num_events == 0 )
		fail_msg("first poll returned 0");
	fprintf(stderr, "first poll: 0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
	fflush(stdout);
	int errnum;
	socklen_t errnumlen = sizeof(errnum);
	if ( getsockopt(fd, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0 )
		fail_msg("getsockopt: SO_ERROR");
	errno = errnum;
	if ( errnum )
		warn("SO_ERROR");
	else
		warnx("SO_ERROR: no error");
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("second poll");
	if ( num_events == 0 )
		fail_msg("second poll returned 0");
	fprintf(stderr, "second poll: 0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, and then test if poll delivers the asynchronous
   error. */
static void ostest_connect_send_error_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("send");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, and then test if connect delivers the asynchronous
   error. */
static void ostest_connect_send_error_reconnect(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("send");
	usleep(50000);
	struct sockaddr_in cos;
	memset(&cos, 0, sizeof(cos));
	cos.sin_family = AF_INET;
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	cos.sin_port = htobe16(65534);
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, and then test if recv delivers the asynchronous
   error. */
static void ostest_connect_send_error_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("send");
	usleep(50000);
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	if ( amount == 0 )
		puts("EOF");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, send another packet, and send yet another
   packet, and test which send call get the error and if the error is sticky. */
static void ostest_connect_send_error_send_send(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("first send");
	usleep(50000);
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("second send");
	else
		warnx("second send: no error");
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("third send");
	else
		warnx("third send: no error");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, and then test if send delivers the asynchronous
   error. */
static void ostest_connect_send_error_send(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("first send");
	usleep(50000);
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("second send");
	else
		warnx("second send: no error");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, shutdown for reading, and then test receiving
   a datagram. */
static void ostest_connect_send_error_shutdown_r_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_RD) < 0 )
		fail_msg("shutdown");
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, shutdown for reading, and then test sending
   a datagram. */
static void ostest_connect_send_error_shutdown_r_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("first send");
	usleep(50000);
	if ( shutdown(fd, SHUT_RD) < 0 )
		fail_msg("shutdown");
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("second send");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, shutdown for reading and writing, and then test
   receiving a datagram. */
static void ostest_connect_send_error_shutdown_rw_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, shutdown for reading and writing, and then test
   sending a datagram. */
static void ostest_connect_send_error_shutdown_rw_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("first send");
	usleep(50000);
	if ( shutdown(fd, SHUT_RDWR) < 0 )
		fail_msg("shutdown");
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("second send");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, shutdown for reading and writing, and then test
   getting the error with SO_ERROR. */
static void ostest_connect_send_error_shutdown_rw_so_error(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_RDWR) < 0 )
		fail_msg("shutdown");
	int errnum;
	socklen_t errnumlen = sizeof(errnum);
	if ( getsockopt(fd, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0 )
		fail_msg("getsockopt: SO_ERROR");
	errno = errnum;
	if ( errnum )
		warn("SO_ERROR");
	else
		warnx("SO_ERROR: no error");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, shutdown for writing, and then test receiving
   a datagram. */
static void ostest_connect_send_error_shutdown_w_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_WR) < 0 )
		fail_msg("shutdown");
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, shutdown for writing, and then test sending
   a datagram. */
static void ostest_connect_send_error_shutdown_w_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("first send");
	usleep(50000);
	if ( shutdown(fd, SHUT_WR) < 0 )
		fail_msg("shutdown");
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("second send");
}

/* Connect to loopback address port 65535, send a datagram, and expect an ICMP
   connection refused packet, get error with SO_ERROR, send a datagram, expect
   another error, and then test if sending a datagram again receives the second
   error. */
static void ostest_connect_send_error_so_error_send_send(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("first send");
	usleep(50000);
	int errnum;
	socklen_t errnumlen = sizeof(errnum);
	if ( getsockopt(fd, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0 )
		fail_msg("getsockopt: SO_ERROR");
	errno = errnum;
	if ( errnum )
		warn("SO_ERROR");
	else
		warnx("SO_ERROR: no error");
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("second send");
	else
		warnx("second send: no error");
	usleep(50000);
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		warn("third send");
	else
		warnx("third send: no error");
}

/* Connect to loopback address port 65535 and then test sendto with a NULL
   address parameter. */
static void ostest_connect_sendto_null(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0, NULL, 0) < 0 )
		fail_msg("sendto");
}

/* Connect to loopback address port 65535 and then test sendto with another
   address (loopback address port 65534). */
static void ostest_connect_sendto_other(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in cos;
	memset(&cos, 0, sizeof(cos));
	cos.sin_family = AF_INET;
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	cos.sin_port = htobe16(65534);
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("sendto");
}

/* Connect to loopback address port 65535 and then test sendto with the same
   address. */
static void ostest_connect_sendto_same(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("sendto");
}

/* Connect to loopback address port 65535, shutdown for reading, and then test
   receiving a datagram. */
static void ostest_connect_shutdown_r_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	if ( shutdown(fd, SHUT_RD) )
		fail_msg("shutdown");
	char x;
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
}

/* Connect to loopback address port 65535, shutdown for reading, and then test
   sending a datagram. */
static void ostest_connect_shutdown_r_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	if ( shutdown(fd, SHUT_RD) )
		fail_msg("shutdown");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
}

/* Connect to loopback address port 65535, shutdown for reading, unconnect, and
   then test receiving a datagram. */
static void ostest_connect_shutdown_r_unconnect_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	if ( shutdown(fd, SHUT_RD) )
		fail_msg("shutdown");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	char x;
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
}

/* Connect to loopback address port 65535, shutdown for reading, unconnect, and
   then test sending a datagram. */
static void ostest_connect_shutdown_r_unconnect_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	if ( shutdown(fd, SHUT_RD) )
		fail_msg("shutdown");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("sendto");
}

/* Connect to loopback address port 65535, shutdown for reading and writing, and
   then test reconnecting to loopback address port 65534. */
static void ostest_connect_shutdown_reconnect(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
	struct sockaddr_in cos;
	memset(&cos, 0, sizeof(cos));
	cos.sin_family = AF_INET;
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	cos.sin_port = htobe16(65534);
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
}

/* Connect to loopback address port 65535, shutdown for reading and writing,
   reconnect to loopback address port 65534, and then test sending a
   datagram. */
static void ostest_connect_shutdown_rw_reconnect_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
	struct sockaddr_in cos;
	memset(&cos, 0, sizeof(cos));
	cos.sin_family = AF_INET;
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	cos.sin_port = htobe16(65534);
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
}

/* Connect to loopback address port 65535, shutdown for reading and writing, and
   then test receiving a datagram. */
static void ostest_connect_shutdown_rw_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
	char x;
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
}

/* Connect to loopback address port 65535, shutdown for reading and writing, and
   then test sending a datagram. */
static void ostest_connect_shutdown_rw_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
}

/* Connect to loopback address port 65535, shutdown for reading and writing,
   unconnect, and then test receiving a datagram. */
static void ostest_connect_shutdown_rw_unconnect_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	char x;
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
}

/* Connect to loopback address port 65535, shutdown for reading and writing,
   unconnect, and then test sending a datagram. */
static void ostest_connect_shutdown_rw_unconnect_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("sendto");
}

/* Connect to loopback address port 65535, shutdown for writing, and then test
   receiving a datagram. */
static void ostest_connect_shutdown_w_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	if ( shutdown(fd, SHUT_WR) )
		fail_msg("shutdown");
	char x;
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
}

/* Connect to loopback address port 65535, shutdown for writing, and then test
   sending a datagram. */
static void ostest_connect_shutdown_w_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	if ( shutdown(fd, SHUT_WR) )
		fail_msg("shutdown");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
}

/* Connect to loopback address port 65535, shutdown for writing, unconnect, and
   then test receiving a datagram. */
static void ostest_connect_shutdown_w_unconnect_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	if ( shutdown(fd, SHUT_WR) )
		fail_msg("shutdown");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	char x;
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
}

/* Connect to loopback address port 65535, shutdown for writing, unconnect, and
   then test sending a datagram. */
static void ostest_connect_shutdown_w_unconnect_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	if ( shutdown(fd, SHUT_WR) )
		fail_msg("shutdown");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("sendto");
}

/* Connect to loopback address port 65535 and then test shutdown for reading
   and writing. */
static void ostest_connect_shutdown(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
}

/* Connect to loopback address port 65535, unconnect, and then test the remote
   address. */
static void ostest_connect_unconnect_getpeername(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getpeername(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getpeername");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "%s:%s\n", host, port);
}

/* Connect to loopback address port 65535, unconnect, and then test the local
   address. */
static void ostest_connect_unconnect_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Connect to loopback address port 65535, then test if unconnect works if the
   unconnect address is a sa_family_t. */
static void ostest_connect_unconnect_sa_family(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	sa_family_t family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &family, sizeof(family)) < 0 )
		fail_msg("second connect");
}

/* Connect to loopback address port 65535, unconnect, shutdown for reading, and
   then test receiving a datagram. */
static void ostest_connect_unconnect_shutdown_r_recv(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	if ( shutdown(fd, SHUT_RD) )
		fail_msg("shutdown");
	char x;
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
}

/* Connect to loopback address port 65535, unconnect, shutdown for reading, and
   then test sending a datagram to loopback address port 65535. */
static void ostest_connect_unconnect_shutdown_r_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	if ( shutdown(fd, SHUT_RD) )
		fail_msg("shutdown");
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("sendto");
}

/* Connect to loopback address port 65535, unconnect, shutdown for reading and
   writing, and then test receiving a datagram. */
static void ostest_connect_unconnect_shutdown_rw_recv(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
	char x;
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
}

/* Connect to loopback address port 65535, unconnect, shutdown for reading and
   writing, and then test sending a datagram to loopback address port 65535. */
static void ostest_connect_unconnect_shutdown_rw_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("sendto");
}

/* Connect to loopback address port 65535, unconnect, shutdown for writing, and
   then test receiving a datagram. */
static void ostest_connect_unconnect_shutdown_w_recv(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	if ( shutdown(fd, SHUT_WR) )
		fail_msg("shutdown");
	char x;
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
}

/* Connect to loopback address port 65535, unconnect, shutdown for writing, and
   then test sending a datagram to loopback address port 65535. */
static void ostest_connect_unconnect_shutdown_w_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	if ( shutdown(fd, SHUT_WR) )
		fail_msg("shutdown");
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("sendto");
}

/* Connect to loopback address port 65535, then test if unconnect works if the
   unconnect address is a struct sockaddr_in. */
static void ostest_connect_unconnect_sockaddr_in(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr_in cos;
	memset(&cos, 0, sizeof(sin));
	cos.sin_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
}

/* Connect to loopback address port 65535, then test if unconnect works if the
   unconnect address is a struct sockaddr_sockaddr. */
static void ostest_connect_unconnect_sockaddr_storage(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr_storage cos;
	memset(&cos, 0, sizeof(cos));
	cos.ss_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
}

/* Connect to loopback address port 65535, then test if unconnect works if the
   unconnect address is a struct sockaddr. */
static void ostest_connect_unconnect_sockaddr(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(sin));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
}

/* Connect to loopback address port 65535, unconnect, and then test unconnecting
   again. */
static void ostest_connect_unconnect_unconnect(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("third connect");
}

/* Connect to loopback address port 65535, and then test unconnecting. */
static void ostest_connect_unconnect(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
}

/* Connect to a public internet address, and then test if the socket as bound
   to a network interface using SO_BINDTODEVICE.  */
static void ostest_connect_wan_get_so_bindtodevice(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(BLACKHOLE_HOST);
	sin.sin_port = htobe16(BLACKHOLE_PORT);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
#ifdef SO_BINDTODEVICE
	char ifname[IF_NAMESIZE + 1];
	socklen_t ifnamelen = sizeof(ifname);
	if ( getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, &ifnamelen) < 0 )
		fail_msg("getsockopt: SO_BINDTODEVICE");
	ifname[ifnamelen] = '\0';
	puts(ifname);
#else
	errno = ENOSYS;
	fail_msg("getsockopt: SO_BINDTODEVICE");
#endif
}

/* Connect to a public internet address, then test the local address. */
static void ostest_connect_wan_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(BLACKHOLE_HOST);
	sin.sin_port = htobe16(BLACKHOLE_PORT);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Connect to a public internet address, send a datagram, then testing
   reconnecting to the loopback address port 65535. */
static void ostest_connect_wan_send_reconnect_loopback_send(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(BLACKHOLE_HOST);
	sin.sin_port = htobe16(BLACKHOLE_PORT);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("first send");
	struct sockaddr_in cos;
	memset(&cos, 0, sizeof(cos));
	cos.sin_family = AF_INET;
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	cos.sin_port = htobe16(65535);
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	char y = 'y';
	if ( send(fd, &y, sizeof(y), 0) < 0 )
		fail_msg("second send");
}

/* Connect to a public internet address, unconnect, then test rebinding to the
   any address port 0 and printing the remote address. */
static void ostest_connect_wan_unconnect_rebind_any_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(BLACKHOLE_HOST);
	sin.sin_port = htobe16(BLACKHOLE_PORT);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	struct sockaddr_in foo;
	memset(&foo, 0, sizeof(foo));
	foo.sin_family = AF_INET;
	foo.sin_addr.s_addr = htobe32(INADDR_ANY);
	foo.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Connect to a public internet address, unconnect, then test rebinding to the
   any address port 0 and printing the local address. */
static void ostest_connect_wan_unconnect_rebind_same_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(BLACKHOLE_HOST);
	sin.sin_port = htobe16(BLACKHOLE_PORT);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first connect");
	struct sockaddr_in assigned;
	socklen_t assignedlen = sizeof(assigned);
	if ( getsockname(fd, (struct sockaddr*) &assigned, &assignedlen) < 0 )
		fail_msg("getsockname");
	struct sockaddr cos;
	memset(&cos, 0, sizeof(cos));
	cos.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("second connect");
	if ( bind(fd, (const struct sockaddr*) &assigned, sizeof(assigned)) < 0 )
		fail_msg("bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("second getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Test sending from the internet to the loopback network. */
static void ostest_cross_netif_lan_send_loopback_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(BLACKHOLE_HOST);
	sin.sin_port = htobe16(BLACKHOLE_PORT);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	close(fd);
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in cos;
	memset(&cos, 0, sizeof(cos));
	cos.sin_family = AF_INET;
	cos.sin_addr.s_addr = local.sin_addr.s_addr;
	cos.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("first bind");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	struct sockaddr_in tan;
	memset(&tan, 0, sizeof(tan));
	tan.sin_family = AF_INET;
	tan.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	tan.sin_port = htobe16(0);
	if ( bind(fd2, (const struct sockaddr*) &tan, sizeof(tan)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in fd2addr;
	socklen_t fd2addrlen = sizeof(fd2addr);
	if ( getsockname(fd2, (struct sockaddr*) &fd2addr, &fd2addrlen) < 0 )
		fail_msg("second getsockname");
	char x = 'x';
	if ( sendto(fd1, &x, sizeof(x), 0,
	            (const struct sockaddr*) &fd2addr, sizeof(fd2addr)) < 0 )
		fail_msg("sendto");
	usleep(50000);
	int errnum;
	socklen_t errnumlen = sizeof(errnum);
	if ( getsockopt(fd1, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0 )
		fail_msg("getsockopt: SO_ERROR");
	errno = errnum;
	if ( errnum )
		fail_msg("SO_ERROR");
	struct sockaddr_in sender;
	socklen_t senderlen = sizeof(sender);
	char c;
	ssize_t amount = recvfrom(fd2, &c, sizeof(c), MSG_DONTWAIT,
	                          (struct sockaddr*) &sender, &senderlen);
	if ( amount < 0 )
		fail_msg("recvfrom");
	else if ( amount == 0 )
		fail_msg("recvfrom: EOF");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &sender, senderlen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, ": ");
	if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes", amount);
	else if ( c == 'x' )
		putchar(x);
	else
		fprintf(stderr, "recv wrong byte");
	putchar('\n');
}

/* Test sending from the loopback network to the internet. */
static void ostest_cross_netif_loopback_send_lan_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(BLACKHOLE_HOST);
	sin.sin_port = htobe16(BLACKHOLE_PORT);
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("connect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	close(fd);
	int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd1 < 0 )
		fail_msg("first socket");
	struct sockaddr_in cos;
	memset(&cos, 0, sizeof(cos));
	cos.sin_family = AF_INET;
	cos.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	cos.sin_port = htobe16(0);
	if ( bind(fd1, (const struct sockaddr*) &cos, sizeof(cos)) < 0 )
		fail_msg("first bind");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	struct sockaddr_in tan;
	memset(&tan, 0, sizeof(tan));
	tan.sin_family = AF_INET;
	tan.sin_addr.s_addr = local.sin_addr.s_addr;
	tan.sin_port = htobe16(0);
	if ( bind(fd2, (const struct sockaddr*) &tan, sizeof(tan)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in fd2addr;
	socklen_t fd2addrlen = sizeof(fd2addr);
	if ( getsockname(fd2, (struct sockaddr*) &fd2addr, &fd2addrlen) < 0 )
		fail_msg("second getsockname");
	char x = 'x';
	if ( sendto(fd1, &x, sizeof(x), 0,
	            (const struct sockaddr*) &fd2addr, sizeof(fd2addr)) < 0 )
		fail_msg("sendto");
	usleep(50000);
	int errnum;
	socklen_t errnumlen = sizeof(errnum);
	if ( getsockopt(fd1, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0 )
		fail_msg("getsockopt: SO_ERROR");
	errno = errnum;
	if ( errnum )
		fail_msg("SO_ERROR");
	struct sockaddr_in sender;
	socklen_t senderlen = sizeof(sender);
	char c;
	ssize_t amount = recvfrom(fd2, &c, sizeof(c), MSG_DONTWAIT,
	                          (struct sockaddr*) &sender, &senderlen);
	if ( amount < 0 )
		fail_msg("recvfrom");
	else if ( amount == 0 )
		fail_msg("recvfrom: EOF");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &sender, senderlen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, ": ");
	if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes", amount);
	else if ( c == 'x' )
		putchar(x);
	else
		fprintf(stderr, "recv wrong byte");
	putchar('\n');
}

/* Test whether a freshly made socket is bound to a device according to
   SO_BINDTODEVICE. */
static void ostest_get_so_bindtodevice(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
#ifdef SO_BINDTODEVICE
	char ifname[IF_NAMESIZE + 1];
	socklen_t ifnamelen = sizeof(ifname);
	if ( getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, &ifnamelen) < 0 )
		fail_msg("getsockopt: SO_BINDTODEVICE");
	ifname[ifnamelen] = '\0';
	puts(ifname);
#else
	errno = ENOSYS;
	fail_msg("getsockopt: SO_BINDTODEVICE");
#endif
}

/* Test remote address on freshly made socket. */
static void ostest_getpeername(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getpeername(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getpeername");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "%s:%s\n", host, port);
}

/* Test the local address of a freshly made socket. */
static void ostest_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Test if listen fails with ENOTSUP. */
static void ostest_listen(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	if ( listen(fd, 1) < 0 )
		fail_msg("listen");
}

/* Create two loopback address sockets connected to each other, and then test
   the poll bits on the first socket. */
static void ostest_pair_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, and then test the poll bits on
   the first socket. */
static void ostest_pair_send_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, and then test receiving a
   datagram on the first socket. */
static void ostest_pair_send_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes\n", amount);
	else if ( x != 'x' )
		fprintf(stderr, "recv wrong byte");
	else
		fprintf(stderr, "%c\n", x);
}

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, shutdown the first socket for
   reading, and then test the poll bits on the first socket. */
static void ostest_pair_send_shutdown_r_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_RD) < 0 )
		fail_msg("shutdown");
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, shutdown the first socket for
   reading, and then test receiving a datagram on the first socket. */
static void ostest_pair_send_shutdown_r_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_RD) < 0 )
		fail_msg("shutdown");
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes\n", amount);
	else if ( x != 'x' )
		fprintf(stderr, "recv wrong byte");
	else
		fprintf(stderr, "%c\n", x);
}

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, shutdown the first socket for
   reading and writing, and then test the poll bits on the first socket. */
static void ostest_pair_send_shutdown_rw_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_RDWR) < 0 )
		fail_msg("shutdown");
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, shutdown the first socket for
   reading and writing, and then test receiving a datagram on the first
   socket. */
static void ostest_pair_send_shutdown_rw_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_RDWR) < 0 )
		fail_msg("shutdown");
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes\n", amount);
	else if ( x != 'x' )
		fprintf(stderr, "recv wrong byte");
	else
		fprintf(stderr, "%c\n", x);
}

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, shutdown the first socket for
   writing, and then test the poll bits on the first socket. */
static void ostest_pair_send_shutdown_w_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_WR) < 0 )
		fail_msg("shutdown");
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, shutdown the first socket for
   writing, and then test receiving a datagram on the first socket. */
static void ostest_pair_send_shutdown_w_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	if ( shutdown(fd, SHUT_WR) < 0 )
		fail_msg("shutdown");
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes\n", amount);
	else if ( x != 'x' )
		fprintf(stderr, "recv wrong byte");
	else
		fprintf(stderr, "%c\n", x);
}

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for reading, and then test the poll bits on the first socket. */
static void ostest_pair_shutdown_r_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	if ( shutdown(fd, SHUT_RD) < 0 )
		fail_msg("shutdown");
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for reading, send a datagram from the second socket to the first
   socket, and then test the poll bits on the first socket. */
static void ostest_pair_shutdown_r_send_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	if ( shutdown(fd, SHUT_RD) < 0 )
		fail_msg("shutdown");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for reading, send a datagram from the second socket to the first
   socket, and then receive a datagram on the first socket. */
static void ostest_pair_shutdown_r_send_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	if ( shutdown(fd, SHUT_RD) < 0 )
		fail_msg("shutdown");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes\n", amount);
	else if ( x != 'x' )
		fprintf(stderr, "recv wrong byte");
	else
		fprintf(stderr, "%c\n", x);
}

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for reading and writing, and then test the poll bits on the
   first socket. */
static void ostest_pair_shutdown_rw_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	if ( shutdown(fd, SHUT_RDWR) < 0 )
		fail_msg("shutdown");
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for reading and writing, send a datagram from the second socket
   to the first socket, and then test the poll bits on the first socket. */
static void ostest_pair_shutdown_rw_send_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	if ( shutdown(fd, SHUT_RDWR) < 0 )
		fail_msg("shutdown");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for reading and writing, send a datagram from the second socket
   to the first socket, and then receive a datagram on the first socket. */
static void ostest_pair_shutdown_rw_send_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	if ( shutdown(fd, SHUT_RDWR) < 0 )
		fail_msg("shutdown");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes\n", amount);
	else if ( x != 'x' )
		fprintf(stderr, "recv wrong byte");
	else
		fprintf(stderr, "%c\n", x);
}

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for writing, and then test the poll bits on the first socket. */
static void ostest_pair_shutdown_w_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	if ( shutdown(fd, SHUT_WR) < 0 )
		fail_msg("shutdown");
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for writing, send a datagram from the second socket to the first
   socket, and then test the poll bits on the first socket. */
static void ostest_pair_shutdown_w_send_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	if ( shutdown(fd, SHUT_WR) < 0 )
		fail_msg("shutdown");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for writing, send a datagram from the second socket to the first
   socket, and then receive a datagram on the first socket. */
static void ostest_pair_shutdown_w_send_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	if ( shutdown(fd, SHUT_WR) < 0 )
		fail_msg("shutdown");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes\n", amount);
	else if ( x != 'x' )
		fprintf(stderr, "recv wrong byte");
	else
		fprintf(stderr, "%c\n", x);
}

/* Test poll bits on a freshly made socket. */
static void ostest_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Receive a datagram on a freshly made socket and then test the local
   address. */
static void ostest_recvfrom_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	socklen_t sinlen = sizeof(sin);
	char x;
	if ( recvfrom(fd, &x, sizeof(x), MSG_DONTWAIT,
	              (struct sockaddr*) &sin, &sinlen) < 0 )
	{
		if ( errno != EAGAIN && errno != EWOULDBLOCK )
			fail_msg("recvfrom");
	}
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Test sending a datagram without a specified destination. */
static void ostest_send(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	char x = 'x';
	if ( send(fd, &x, sizeof(x), 0) < 0 )
		fail_msg("send");
	usleep(50000);
	int errnum;
	socklen_t errnumlen = sizeof(errnum);
	if ( getsockopt(fd, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0 )
		fail_msg("getsockopt: SO_ERROR");
	if ( errnum )
	{
		errno = errnum;
		fail_msg("SO_ERROR");
	}
}

/* Test sending a datagram to the any address. */
static void ostest_sendto_any_so_error(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_ANY);
	sin.sin_port = htobe16(65535);
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("sendto");
	usleep(50000);
	int errnum;
	socklen_t errnumlen = sizeof(errnum);
	if ( getsockopt(fd, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0 )
		fail_msg("getsockopt: SO_ERROR");
	if ( errnum )
	{
		errno = errnum;
		fail_msg("SO_ERROR");
	}
}

/* Send a datagram to loopback address port 65535 and then test the local
   address. */
static void ostest_sendto_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(65535);
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("sendto");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Test sending a datagram to the loopback address port 0. */
static void ostest_sendto_loopback_0_so_error(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("sendto");
	usleep(50000);
	int errnum;
	socklen_t errnumlen = sizeof(errnum);
	if ( getsockopt(fd, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0 )
		fail_msg("getsockopt: SO_ERROR");
	if ( errnum )
	{
		errno = errnum;
		fail_msg("SO_ERROR");
	}
}

/* Test sending a datagram without a specified destination. */
static void ostest_sendto_null(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0, NULL, 0) < 0 )
		fail_msg("sendto");
	usleep(50000);
	int errnum;
	socklen_t errnumlen = sizeof(errnum);
	if ( getsockopt(fd, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0 )
		fail_msg("getsockopt: SO_ERROR");
	if ( errnum )
	{
		errno = errnum;
		fail_msg("SO_ERROR");
	}
}

/* Shut down for reading and then test receiving a datagram. */
static void ostest_shutdown_r_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	if ( shutdown(fd, SHUT_RD) )
		fail_msg("shutdown");
	char x;
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
}

/* Shut down for reading and then test sending a datagram. */
static void ostest_shutdown_r_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	if ( shutdown(fd, SHUT_RD) )
		fail_msg("shutdown");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(BLACKHOLE_HOST);
	sin.sin_port = htobe16(BLACKHOLE_PORT);
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("sendto");
}

/* Shut down for reading and writing and then test receiving a datagram. */
static void ostest_shutdown_rw_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
	char x;
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
}

/* Shut down for reading and writing and then test sending a datagram. */
static void ostest_shutdown_rw_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(BLACKHOLE_HOST);
	sin.sin_port = htobe16(BLACKHOLE_PORT);
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("sendto");
}

/* Shut down for writing and then test receiving a datagram. */
static void ostest_shutdown_w_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	if ( shutdown(fd, SHUT_WR) )
		fail_msg("shutdown");
	char x;
	ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
}

/* Shut down for writing and then test sending a datagram. */
static void ostest_shutdown_w_send(void **state)
{     (void) state;
	signal(SIGPIPE, sigpipe);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	if ( shutdown(fd, SHUT_WR) )
		fail_msg("shutdown");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(BLACKHOLE_HOST);
	sin.sin_port = htobe16(BLACKHOLE_PORT);
	char x = 'x';
	if ( sendto(fd, &x, sizeof(x), 0,
	            (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("sendto");
}

/* Test shutdown for read and write on a freshly made socket. */
static void ostest_shutdown(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	if ( shutdown(fd, SHUT_RDWR) )
		fail_msg("shutdown");
}

/* Test SO_ERROR on a freshly made socket. */
static void ostest_so_error(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	int errnum;
	socklen_t errnumlen = sizeof(errnum);
	if ( getsockopt(fd, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0 )
		fail_msg("getsockopt: SO_ERROR");
	errno = errnum;
	if ( errnum )
		warn("SO_ERROR");
	else
		warnx("SO_ERROR: no error");
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, connect the
   first socket to the second socket, send 'x' on the second socket to the
   first socket, and then test the poll bits on the first socket. */
static void ostest_trio_connect_send_right_x_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd3 < 0 )
		fail_msg("second socket");
	if ( bind(fd3, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local3;
	socklen_t locallen3 = sizeof(local3);
	if ( getsockname(fd3, (struct sockaddr*) &local3, &locallen3) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd3, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send of x");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, connect the
   first socket to the second socket, send 'x' on the second socket to the
   first socket, and then test if 'x' is received on the first socket. */
static void ostest_trio_connect_send_right_x_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd3 < 0 )
		fail_msg("second socket");
	if ( bind(fd3, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local3;
	socklen_t locallen3 = sizeof(local3);
	if ( getsockname(fd3, (struct sockaddr*) &local3, &locallen3) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd3, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send of x");
	usleep(50000);
	char z;
	ssize_t amount = recv(fd, &z, sizeof(z), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes\n", amount);
	else if ( z == 'x' || z == 'y' )
		fprintf(stderr, "%c\n", z);
	else
		fprintf(stderr, "recv wrong byte");
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, connect the
   first socket to the second socket, send 'y' on the third socket to the
   first socket, and then test the poll bits on the first socket. */
static void ostest_trio_connect_send_wrong_y_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd3 < 0 )
		fail_msg("second socket");
	if ( bind(fd3, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local3;
	socklen_t locallen3 = sizeof(local3);
	if ( getsockname(fd3, (struct sockaddr*) &local3, &locallen3) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd3, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	char y = 'y';
	if ( send(fd3, &y, sizeof(y), 0) < 0 )
		fail_msg("send of y");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, connect the
   first socket to the second socket, send 'y' on the third socket to the
   first socket, and then test if 'y' is received on the first socket. */
static void ostest_trio_connect_send_wrong_y_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd3 < 0 )
		fail_msg("second socket");
	if ( bind(fd3, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local3;
	socklen_t locallen3 = sizeof(local3);
	if ( getsockname(fd3, (struct sockaddr*) &local3, &locallen3) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd3, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	char y = 'y';
	if ( send(fd3, &y, sizeof(y), 0) < 0 )
		fail_msg("send of y");
	usleep(50000);
	char z;
	ssize_t amount = recv(fd, &z, sizeof(z), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes\n", amount);
	else if ( z == 'x' || z == 'y' )
		fprintf(stderr, "%c\n", z);
	else
		fprintf(stderr, "recv wrong byte");
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, connect the
   first socket to the second socket, send 'y' on the third socket to the
   first socket, send 'x' on the second socket to the first socket, and then
   test the poll bits on the first socket. */
static void ostest_trio_connect_send_wrong_y_send_right_x_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd3 < 0 )
		fail_msg("second socket");
	if ( bind(fd3, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local3;
	socklen_t locallen3 = sizeof(local3);
	if ( getsockname(fd3, (struct sockaddr*) &local3, &locallen3) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd3, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	char y = 'y';
	if ( send(fd3, &y, sizeof(y), 0) < 0 )
		fail_msg("send of y");
	usleep(50000);
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send of x");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, connect the
   first socket to the second socket, send 'y' on the third socket to the
   first socket, send 'x' on the second socket to the first socket, and then
   test whether 'x' or 'y' is received on the first socket. */
static void ostest_trio_connect_send_wrong_y_send_right_x_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd3 < 0 )
		fail_msg("second socket");
	if ( bind(fd3, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local3;
	socklen_t locallen3 = sizeof(local3);
	if ( getsockname(fd3, (struct sockaddr*) &local3, &locallen3) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd3, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	char y = 'y';
	if ( send(fd3, &y, sizeof(y), 0) < 0 )
		fail_msg("send of y");
	usleep(50000);
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send of x");
	usleep(50000);
	char z;
	ssize_t amount = recv(fd, &z, sizeof(z), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes\n", amount);
	else if ( z == 'x' || z == 'y' )
		fprintf(stderr, "%c\n", z);
	else
		fprintf(stderr, "recv wrong byte");
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'x' on
   the second socket to the first socket, and then test the poll bits on the
   first socket. */
static void ostest_trio_send_right_x_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd3 < 0 )
		fail_msg("second socket");
	if ( bind(fd3, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local3;
	socklen_t locallen3 = sizeof(local3);
	if ( getsockname(fd3, (struct sockaddr*) &local3, &locallen3) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd3, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send of x");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'x' on
   the second socket to the first socket, and then test receiving 'x' on the
   first socket. */
static void ostest_trio_send_right_x_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd3 < 0 )
		fail_msg("second socket");
	if ( bind(fd3, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local3;
	socklen_t locallen3 = sizeof(local3);
	if ( getsockname(fd3, (struct sockaddr*) &local3, &locallen3) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd3, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send of x");
	usleep(50000);
	char z;
	ssize_t amount = recv(fd, &z, sizeof(z), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes\n", amount);
	else if ( z == 'x' || z == 'y' )
		fprintf(stderr, "%c\n", z);
	else
		fprintf(stderr, "recv wrong byte");
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'x' on
   the second socket to the first socket, send 'y' on the third socket to the
   first socket, and then test the poll bits on the first socket. */
static void ostest_trio_send_right_x_send_wrong_y_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd3 < 0 )
		fail_msg("second socket");
	if ( bind(fd3, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local3;
	socklen_t locallen3 = sizeof(local3);
	if ( getsockname(fd3, (struct sockaddr*) &local3, &locallen3) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd3, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send of x");
	usleep(50000);
	char y = 'y';
	if ( send(fd3, &y, sizeof(y), 0) < 0 )
		fail_msg("send of y");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'x' on
   the second socket to the first socket, send 'y' on the third socket to the
   first socket, and then test receiving 'x' on the first socket. */
static void ostest_trio_send_right_x_send_wrong_y_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd3 < 0 )
		fail_msg("second socket");
	if ( bind(fd3, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local3;
	socklen_t locallen3 = sizeof(local3);
	if ( getsockname(fd3, (struct sockaddr*) &local3, &locallen3) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd3, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send of x");
	usleep(50000);
	char y = 'y';
	if ( send(fd3, &y, sizeof(y), 0) < 0 )
		fail_msg("send of y");
	usleep(50000);
	char z;
	ssize_t amount = recv(fd, &z, sizeof(z), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes\n", amount);
	else if ( z == 'x' || z == 'y' )
		fprintf(stderr, "%c\n", z);
	else
		fprintf(stderr, "recv wrong byte");
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'y' on
   the third socket to the first socket, connect the first socket to the second
   socket, and then test the poll bits on the first socket. */
static void ostest_trio_send_wrong_y_connect_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd3 < 0 )
		fail_msg("second socket");
	if ( bind(fd3, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local3;
	socklen_t locallen3 = sizeof(local3);
	if ( getsockname(fd3, (struct sockaddr*) &local3, &locallen3) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd3, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char y = 'y';
	if ( send(fd3, &y, sizeof(y), 0) < 0 )
		fail_msg("send of y");
	usleep(50000);
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'y' on
   the third socket to the first socket, connect the first socket to the second
   socket, and then test if 'y' is received on the first socket. */
static void ostest_trio_send_wrong_y_connect_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd3 < 0 )
		fail_msg("second socket");
	if ( bind(fd3, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local3;
	socklen_t locallen3 = sizeof(local3);
	if ( getsockname(fd3, (struct sockaddr*) &local3, &locallen3) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd3, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char y = 'y';
	if ( send(fd3, &y, sizeof(y), 0) < 0 )
		fail_msg("send of y");
	usleep(50000);
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	char z;
	ssize_t amount = recv(fd, &z, sizeof(z), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes\n", amount);
	else if ( z == 'x' || z == 'y' )
		fprintf(stderr, "%c\n", z);
	else
		fprintf(stderr, "recv wrong byte");
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'y' on
   the third socket to the first socket, send 'x' on the second socket to the
   first socket, connect the first socket to the second socket, and then test
   the poll bits on the first socket. */
static void ostest_trio_send_wrong_y_connect_send_right_x_poll(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd3 < 0 )
		fail_msg("second socket");
	if ( bind(fd3, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local3;
	socklen_t locallen3 = sizeof(local3);
	if ( getsockname(fd3, (struct sockaddr*) &local3, &locallen3) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd3, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char y = 'y';
	if ( send(fd3, &y, sizeof(y), 0) < 0 )
		fail_msg("send of y");
	usleep(50000);
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send of x");
	usleep(50000);
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	int num_events = poll(&pfd, 1, 0);
	if ( num_events < 0 )
		fail_msg("poll");
	if ( num_events == 0 )
		fail_msg("poll returned 0");
	fprintf(stderr, "0");
	if ( pfd.revents & POLLIN )
		fprintf(stderr, " | POLLIN");
	if ( pfd.revents & POLLPRI )
		fprintf(stderr, " | POLLPRI");
	if ( pfd.revents & POLLOUT )
		fprintf(stderr, " | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
	if ( pfd.revents & POLLRDHUP )
		fprintf(stderr, " | POLLRDHUP");
#endif
	if ( pfd.revents & POLLERR )
		fprintf(stderr, " | POLLERR");
	if ( pfd.revents & POLLHUP )
		fprintf(stderr, " | POLLHUP");
#if POLLRDNORM != POLLIN
	if ( pfd.revents & POLLRDNORM )
		fprintf(stderr, " | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
	if ( pfd.revents & POLLRDBAND )
		fprintf(stderr, " | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
	if ( pfd.revents & POLLWRNORM )
		fprintf(stderr, " | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
	if ( pfd.revents & POLLWRBAND )
		fprintf(stderr, " | POLLWRBAND");
#endif
	putchar('\n');
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'y' on
   the third socket to the first socket, send 'x' on the second socket to the
   first socket, connect the first socket to the second socket, and then test
   if 'x' or 'y' is received on the first socket. */
static void ostest_trio_send_wrong_y_connect_send_right_x_recv(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("first socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
	sin.sin_port = htobe16(0);
	if ( bind(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("first bind");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("first getsockname");
	int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd2 < 0 )
		fail_msg("second socket");
	if ( bind(fd2, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	if ( connect(fd2, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	struct sockaddr_in local2;
	socklen_t locallen2 = sizeof(local2);
	if ( getsockname(fd2, (struct sockaddr*) &local2, &locallen2) < 0 )
		fail_msg("second getsockname");
	int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd3 < 0 )
		fail_msg("second socket");
	if ( bind(fd3, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("second bind");
	struct sockaddr_in local3;
	socklen_t locallen3 = sizeof(local3);
	if ( getsockname(fd3, (struct sockaddr*) &local3, &locallen3) < 0 )
		fail_msg("second getsockname");
	if ( connect(fd3, (const struct sockaddr*) &local, locallen) < 0 )
		fail_msg("second connect");
	char y = 'y';
	if ( send(fd3, &y, sizeof(y), 0) < 0 )
		fail_msg("send of y");
	usleep(50000);
	if ( connect(fd, (const struct sockaddr*) &local2, locallen2) < 0 )
		fail_msg("first connect");
	char x = 'x';
	if ( send(fd2, &x, sizeof(x), 0) < 0 )
		fail_msg("send of x");
	usleep(50000);
	char z;
	ssize_t amount = recv(fd, &z, sizeof(z), MSG_DONTWAIT);
	if ( amount < 0 )
		fail_msg("recv");
	else if ( amount == 0 )
		puts("EOF");
	else if ( amount != 1 )
		fprintf(stderr, "recv %zi bytes\n", amount);
	else if ( z == 'x' || z == 'y' )
		fprintf(stderr, "%c\n", z);
	else
		fprintf(stderr, "recv wrong byte");
}

/* Unconnect a freshly made socket and test its remote address. */
static void ostest_unconnect_getpeername(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr sin;
	memset(&sin, 0, sizeof(sin));
	sin.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("unconnect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getpeername(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getpeername");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "%s:%s\n", host, port);
}

/* Unconnect a freshly made socket and test its local address. */
static void ostest_unconnect_getsockname(void **state)
{     (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr sin;
	memset(&sin, 0, sizeof(sin));
	sin.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("unconnect");
	struct sockaddr_in local;
	socklen_t locallen = sizeof(local);
	if ( getsockname(fd, (struct sockaddr*) &local, &locallen) < 0 )
		fail_msg("getsockname");
	char host[INET_ADDRSTRLEN + 1];
	char port[5 + 1];
	getnameinfo((const struct sockaddr*) &local, locallen, host, sizeof(host),
	            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if ( !strncmp(host, "192.168.", strlen("192.168.")) )
		fprintf(stderr, "192.168.1.x");
	else if ( !strncmp(host, "100.82.", strlen("100.82.")) )
		fprintf(stderr, "192.168.1.x");
	else
		fprintf(stderr, "%s", host);
	fprintf(stderr, ":");
	if ( !strcmp(port, "0") )
		fprintf(stderr, "%s", port);
	else
		fprintf(stderr, "non-zero");
	fprintf(stderr, "\n");
}

/* Test unconnecting a freshly made socket. */
static void ostest_unconnect(void **state)
{
    (void) state;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( fd < 0 )
		fail_msg("socket");
	struct sockaddr sin;
	memset(&sin, 0, sizeof(sin));
	sin.sa_family = AF_UNSPEC;
	if ( connect(fd, (const struct sockaddr*) &sin, sizeof(sin)) < 0 )
		fail_msg("unconnect");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(ostest_accept_nonblock),
        cmocka_unit_test(ostest_accept),
        cmocka_unit_test(ostest_bind_any_0_getpeername),
        cmocka_unit_test(ostest_bind_any_0_getsockname),
        cmocka_unit_test(ostest_bind_any_0_unbind),
        cmocka_unit_test(ostest_bind_any_0),
        cmocka_unit_test(ostest_bind_broadcast_0_getpeername),
        cmocka_unit_test(ostest_bind_broadcast_0_getsockname),
        cmocka_unit_test(ostest_bind_conflict_any_any_so_reuseaddr_both),
        cmocka_unit_test(ostest_bind_conflict_any_any_so_reuseaddr),
        cmocka_unit_test(ostest_bind_conflict_any_any),
        cmocka_unit_test(ostest_bind_conflict_any_broadcast_so_reuseaddr_both),
        cmocka_unit_test(ostest_bind_conflict_any_broadcast_so_reuseaddr),
        cmocka_unit_test(ostest_bind_conflict_any_broadcast),
        cmocka_unit_test(ostest_bind_conflict_any_loopback_so_reuseaddr_both),
        cmocka_unit_test(ostest_bind_conflict_any_loopback_so_reuseaddr),
        cmocka_unit_test(ostest_bind_conflict_any_loopback),
        cmocka_unit_test(ostest_bind_conflict_broadcast_any_so_reuseaddr_both),
        cmocka_unit_test(ostest_bind_conflict_broadcast_any_so_reuseaddr),
        cmocka_unit_test(ostest_bind_conflict_broadcast_any),
        cmocka_unit_test(ostest_bind_conflict_broadcast_broadcast_so_reuseaddr_both),
        cmocka_unit_test(ostest_bind_conflict_broadcast_broadcast_so_reuseaddr),
        cmocka_unit_test(ostest_bind_conflict_broadcast_broadcast),
        cmocka_unit_test(ostest_bind_conflict_broadcast_loopback_so_reuseaddr_both),
        cmocka_unit_test(ostest_bind_conflict_broadcast_loopback_so_reuseaddr),
        cmocka_unit_test(ostest_bind_conflict_broadcast_loopback),
        cmocka_unit_test(ostest_bind_conflict_loopback_any_so_reuseaddr_both),
        cmocka_unit_test(ostest_bind_conflict_loopback_any_so_reuseaddr),
        cmocka_unit_test(ostest_bind_conflict_loopback_any),
        cmocka_unit_test(ostest_bind_conflict_loopback_broadcast_so_reuseaddr_both),
        cmocka_unit_test(ostest_bind_conflict_loopback_broadcast_so_reuseaddr),
        cmocka_unit_test(ostest_bind_conflict_loopback_broadcast),
        cmocka_unit_test(ostest_bind_conflict_loopback_loopback_so_reuseaddr_both),
        cmocka_unit_test(ostest_bind_conflict_loopback_loopback_so_reuseaddr),
        cmocka_unit_test(ostest_bind_conflict_loopback_loopback),
        cmocka_unit_test(ostest_bind_connect_self_send_poll),
        cmocka_unit_test(ostest_bind_connect_self_send_recv),
        cmocka_unit_test(ostest_bind_connect_self_send_shutdown_r_poll),
        cmocka_unit_test(ostest_bind_connect_self_send_shutdown_r_recv_recv),
        cmocka_unit_test(ostest_bind_connect_self_send_shutdown_r_recv),
        cmocka_unit_test(ostest_bind_connect_self_send_shutdown_rw_poll),
        cmocka_unit_test(ostest_bind_connect_self_send_shutdown_rw_recv_recv),
        cmocka_unit_test(ostest_bind_connect_self_send_shutdown_rw_recv),
        cmocka_unit_test(ostest_bind_connect_self_send),
        cmocka_unit_test(ostest_bind_connect_self_shutdown_r_send_poll),
        cmocka_unit_test(ostest_bind_connect_self_shutdown_r_send_recv),
        cmocka_unit_test(ostest_bind_connect_self),
        cmocka_unit_test(ostest_bind_lan_subnet_broadcast),
        cmocka_unit_test(ostest_bind_lan_subnet_first),
        cmocka_unit_test(ostest_bind_lan_subnet_wrong),
        cmocka_unit_test(ostest_bind_loopback_0_getpeername),
        cmocka_unit_test(ostest_bind_loopback_0_getsockname),
        cmocka_unit_test(ostest_bind_loopback_broadcast),
        cmocka_unit_test(ostest_bind_loopback_other),
        cmocka_unit_test(ostest_bind_rebind),
        cmocka_unit_test(ostest_bind_sendto_self_recv),
        cmocka_unit_test(ostest_bind_sendto_self),
        cmocka_unit_test(ostest_bind_socket_sendto_first_poll),
        cmocka_unit_test(ostest_bind_socket_sendto_first_recv),
        cmocka_unit_test(ostest_bind_socket_sendto_first_shutdown_r_poll),
        cmocka_unit_test(ostest_bind_socket_sendto_first_shutdown_r_recv),
        cmocka_unit_test(ostest_bind_socket_sendto_first_shutdown_rw_poll),
        cmocka_unit_test(ostest_bind_socket_sendto_first_shutdown_rw_recv),
        cmocka_unit_test(ostest_bind_socket_sendto_first_shutdown_w_poll),
        cmocka_unit_test(ostest_bind_socket_sendto_first_shutdown_w_recv),
        cmocka_unit_test(ostest_bind_socket_shutdown_r_sendto_first_poll),
        cmocka_unit_test(ostest_bind_socket_shutdown_r_sendto_first_recv),
        cmocka_unit_test(ostest_bind_socket_shutdown_rw_sendto_first_poll),
        cmocka_unit_test(ostest_bind_socket_shutdown_rw_sendto_first_recv),
        cmocka_unit_test(ostest_bind_socket_shutdown_w_sendto_first_poll),
        cmocka_unit_test(ostest_bind_socket_shutdown_w_sendto_first_recv),
        cmocka_unit_test(ostest_connect_any_0_getpeername),
        cmocka_unit_test(ostest_connect_any_0_getsockname),
        cmocka_unit_test(ostest_connect_any_getpeername),
        cmocka_unit_test(ostest_connect_any_getsockname),
        cmocka_unit_test(ostest_connect_broadcast_getpeername_so_broadcast),
        cmocka_unit_test(ostest_connect_broadcast_getpeername),
        cmocka_unit_test(ostest_connect_broadcast_getsockname_so_broadcast),
        cmocka_unit_test(ostest_connect_broadcast_getsockname),
        cmocka_unit_test(ostest_connect_getpeername),
        cmocka_unit_test(ostest_connect_loopback_0_getpeername),
        cmocka_unit_test(ostest_connect_loopback_0_getsockname),
        cmocka_unit_test(ostest_connect_loopback_get_so_bindtodevice),
        cmocka_unit_test(ostest_connect_loopback_getpeername),
        cmocka_unit_test(ostest_connect_loopback_getsockname),
        cmocka_unit_test(ostest_connect_loopback_reconnect_loopback_getsockname),
        cmocka_unit_test(ostest_connect_loopback_reconnect_wan_getsockname),
        cmocka_unit_test(ostest_connect_loopback_unconnect_rebind_any_getsockname),
        cmocka_unit_test(ostest_connect_loopback_unconnect_rebind_loopback_getsockname),
        cmocka_unit_test(ostest_connect_poll),
        cmocka_unit_test(ostest_connect_reconnect_any_getpeername),
        cmocka_unit_test(ostest_connect_reconnect_getpeername),
        cmocka_unit_test(ostest_connect_reconnect_same),
        cmocka_unit_test(ostest_connect_reconnect),
        cmocka_unit_test(ostest_connect_recv),
        cmocka_unit_test(ostest_connect_send_error_accept),
        cmocka_unit_test(ostest_connect_send_error_getpeername),
        cmocka_unit_test(ostest_connect_send_error_getsockname),
        cmocka_unit_test(ostest_connect_send_error_listen),
        cmocka_unit_test(ostest_connect_send_error_poll_poll),
        cmocka_unit_test(ostest_connect_send_error_poll_so_error_poll),
        cmocka_unit_test(ostest_connect_send_error_poll),
        cmocka_unit_test(ostest_connect_send_error_reconnect),
        cmocka_unit_test(ostest_connect_send_error_recv),
        cmocka_unit_test(ostest_connect_send_error_send_send),
        cmocka_unit_test(ostest_connect_send_error_send),
        cmocka_unit_test(ostest_connect_send_error_shutdown_r_recv),
        cmocka_unit_test(ostest_connect_send_error_shutdown_r_send),
        cmocka_unit_test(ostest_connect_send_error_shutdown_rw_recv),
        cmocka_unit_test(ostest_connect_send_error_shutdown_rw_send),
        cmocka_unit_test(ostest_connect_send_error_shutdown_rw_so_error),
        cmocka_unit_test(ostest_connect_send_error_shutdown_w_recv),
        cmocka_unit_test(ostest_connect_send_error_shutdown_w_send),
        cmocka_unit_test(ostest_connect_send_error_so_error_send_send),
        cmocka_unit_test(ostest_connect_sendto_null),
        cmocka_unit_test(ostest_connect_sendto_other),
        cmocka_unit_test(ostest_connect_sendto_same),
        cmocka_unit_test(ostest_connect_shutdown_r_recv),
        cmocka_unit_test(ostest_connect_shutdown_r_send),
        cmocka_unit_test(ostest_connect_shutdown_r_unconnect_recv),
        cmocka_unit_test(ostest_connect_shutdown_r_unconnect_send),
        cmocka_unit_test(ostest_connect_shutdown_reconnect),
        cmocka_unit_test(ostest_connect_shutdown_rw_reconnect_send),
        cmocka_unit_test(ostest_connect_shutdown_rw_recv),
        cmocka_unit_test(ostest_connect_shutdown_rw_send),
        cmocka_unit_test(ostest_connect_shutdown_rw_unconnect_recv),
        cmocka_unit_test(ostest_connect_shutdown_rw_unconnect_send),
        cmocka_unit_test(ostest_connect_shutdown_w_recv),
        cmocka_unit_test(ostest_connect_shutdown_w_send),
        cmocka_unit_test(ostest_connect_shutdown_w_unconnect_recv),
        cmocka_unit_test(ostest_connect_shutdown_w_unconnect_send),
        cmocka_unit_test(ostest_connect_shutdown),
        cmocka_unit_test(ostest_connect_unconnect_getpeername),
        cmocka_unit_test(ostest_connect_unconnect_getsockname),
        cmocka_unit_test(ostest_connect_unconnect_sa_family),
        cmocka_unit_test(ostest_connect_unconnect_shutdown_r_recv),
        cmocka_unit_test(ostest_connect_unconnect_shutdown_r_send),
        cmocka_unit_test(ostest_connect_unconnect_shutdown_rw_recv),
        cmocka_unit_test(ostest_connect_unconnect_shutdown_rw_send),
        cmocka_unit_test(ostest_connect_unconnect_shutdown_w_recv),
        cmocka_unit_test(ostest_connect_unconnect_shutdown_w_send),
        cmocka_unit_test(ostest_connect_unconnect_sockaddr_in),
        cmocka_unit_test(ostest_connect_unconnect_sockaddr_storage),
        cmocka_unit_test(ostest_connect_unconnect_sockaddr),
        cmocka_unit_test(ostest_connect_unconnect_unconnect),
        cmocka_unit_test(ostest_connect_unconnect),
        cmocka_unit_test(ostest_connect_wan_get_so_bindtodevice),
        cmocka_unit_test(ostest_connect_wan_getsockname),
        cmocka_unit_test(ostest_connect_wan_send_reconnect_loopback_send),
        cmocka_unit_test(ostest_connect_wan_unconnect_rebind_any_getsockname),
        cmocka_unit_test(ostest_connect_wan_unconnect_rebind_same_getsockname),
        cmocka_unit_test(ostest_cross_netif_lan_send_loopback_recv),
        cmocka_unit_test(ostest_cross_netif_loopback_send_lan_recv),
        cmocka_unit_test(ostest_get_so_bindtodevice),
        cmocka_unit_test(ostest_getpeername),
        cmocka_unit_test(ostest_getsockname),
        cmocka_unit_test(ostest_listen),
        cmocka_unit_test(ostest_pair_poll),
        cmocka_unit_test(ostest_pair_send_poll),
        cmocka_unit_test(ostest_pair_send_recv),
        cmocka_unit_test(ostest_pair_send_shutdown_r_poll),
        cmocka_unit_test(ostest_pair_send_shutdown_r_recv),
        cmocka_unit_test(ostest_pair_send_shutdown_rw_poll),
        cmocka_unit_test(ostest_pair_send_shutdown_rw_recv),
        cmocka_unit_test(ostest_pair_send_shutdown_w_poll),
        cmocka_unit_test(ostest_pair_send_shutdown_w_recv),
        cmocka_unit_test(ostest_pair_shutdown_r_poll),
        cmocka_unit_test(ostest_pair_shutdown_r_send_poll),
        cmocka_unit_test(ostest_pair_shutdown_r_send_recv),
        cmocka_unit_test(ostest_pair_shutdown_rw_poll),
        cmocka_unit_test(ostest_pair_shutdown_rw_send_poll),
        cmocka_unit_test(ostest_pair_shutdown_rw_send_recv),
        cmocka_unit_test(ostest_pair_shutdown_w_poll),
        cmocka_unit_test(ostest_pair_shutdown_w_send_poll),
        cmocka_unit_test(ostest_pair_shutdown_w_send_recv),
        cmocka_unit_test(ostest_poll),
        cmocka_unit_test(ostest_recvfrom_getsockname),
        cmocka_unit_test(ostest_send),
        cmocka_unit_test(ostest_sendto_any_so_error),
        cmocka_unit_test(ostest_sendto_getsockname),
        cmocka_unit_test(ostest_sendto_loopback_0_so_error),
        cmocka_unit_test(ostest_sendto_null),
        cmocka_unit_test(ostest_shutdown_r_recv),
        cmocka_unit_test(ostest_shutdown_r_send),
        cmocka_unit_test(ostest_shutdown_rw_recv),
        cmocka_unit_test(ostest_shutdown_rw_send),
        cmocka_unit_test(ostest_shutdown_w_recv),
        cmocka_unit_test(ostest_shutdown_w_send),
        cmocka_unit_test(ostest_shutdown),
        cmocka_unit_test(ostest_so_error),
        cmocka_unit_test(ostest_trio_connect_send_right_x_poll),
        cmocka_unit_test(ostest_trio_connect_send_right_x_recv),
        cmocka_unit_test(ostest_trio_connect_send_wrong_y_poll),
        cmocka_unit_test(ostest_trio_connect_send_wrong_y_recv),
        cmocka_unit_test(ostest_trio_connect_send_wrong_y_send_right_x_poll),
        cmocka_unit_test(ostest_trio_connect_send_wrong_y_send_right_x_recv),
        cmocka_unit_test(ostest_trio_send_right_x_poll),
        cmocka_unit_test(ostest_trio_send_right_x_recv),
        cmocka_unit_test(ostest_trio_send_right_x_send_wrong_y_poll),
        cmocka_unit_test(ostest_trio_send_right_x_send_wrong_y_recv),
        cmocka_unit_test(ostest_trio_send_wrong_y_connect_poll),
        cmocka_unit_test(ostest_trio_send_wrong_y_connect_recv),
        cmocka_unit_test(ostest_trio_send_wrong_y_connect_send_right_x_poll),
        cmocka_unit_test(ostest_trio_send_wrong_y_connect_send_right_x_recv),
        cmocka_unit_test(ostest_unconnect_getpeername),
        cmocka_unit_test(ostest_unconnect_getsockname),
        cmocka_unit_test(ostest_unconnect),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
