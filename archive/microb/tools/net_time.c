//#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>		/* for uint64_t */
#include <errno.h>
#include <unistd.h>
//#include <locale.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>

#define NTP_TIMESTAMP_DELTA 2208988800ull
#define LI(packet)   (uint8_t) ((packet.li_vn_mode & 0xC0) >> 6) // (li   & 11 000 000) >> 6
#define VN(packet)   (uint8_t) ((packet.li_vn_mode & 0x38) >> 3) // (vn   & 00 111 000) >> 3
#define MODE(packet) (uint8_t) ((packet.li_vn_mode & 0x07) >> 0) // (mode & 00 000 111) >> 0

#define TIMEOUT 1		/* pause between printing time */
#define NTP_TIMEOUT 5	/* 5 second timeout */

const int NANO_SECONDS_IN_SEC = 1000000000;
int get_sntp_time(char* host_name, time_t time);

// Simple Network Time Protocol (SNTP) Version 4 for IPv4, IPv6 and OSI
// http://www.faqs.org/rfc/rfc4330.txt
int get_sntp_time(char* host_name, time_t time)
{
  struct timeval tv;
  int fd, rc, len, so_error, n;
  int portno = 123;
  fd_set fdset;

  // Structure that defines the 48 byte NTP packet protocol.
  typedef struct
  {

    uint8_t li_vn_mode;      // Eight bits. li, vn, and mode.
                             // li.   Two bits.   Leap indicator.
                             // vn.   Three bits. Version number of the protocol.
                             // mode. Three bits. Client will pick mode 3 for client.

    uint8_t stratum;         // Eight bits. Stratum level of the local clock.
    uint8_t poll;            // Eight bits. Maximum interval between successive messages.
    uint8_t precision;       // Eight bits. Precision of the local clock.

    uint32_t rootDelay;      // 32 bits. Total round trip delay time.
    uint32_t rootDispersion; // 32 bits. Max error aloud from primary clock source.
    uint32_t refId;          // 32 bits. Reference clock identifier.

    uint32_t refTm_s;        // 32 bits. Reference time-stamp seconds.
    uint32_t refTm_f;        // 32 bits. Reference time-stamp fraction of a second.

    uint32_t origTm_s;       // 32 bits. Originate time-stamp seconds.
    uint32_t origTm_f;       // 32 bits. Originate time-stamp fraction of a second.

    uint32_t rxTm_s;         // 32 bits. Received time-stamp seconds.
    uint32_t rxTm_f;         // 32 bits. Received time-stamp fraction of a second.

    uint32_t txTm_s;         // 32 bits and the most important field the client cares about. Transmit time-stamp seconds.
    uint32_t txTm_f;         // 32 bits. Transmit time-stamp fraction of a second.

  } ntp_packet;              // Total: 384 bits or 48 bytes.

  ntp_packet packet = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  memset( &packet, 0, sizeof( ntp_packet ) );
  *( ( char * ) &packet + 0 ) = 0x1b; // Represents 27 in base 10 or 00011011 in base 2.

  struct sockaddr_in serv_addr;
  struct hostent *server;

  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) {
    fprintf(stderr, "ERROR: %s, %d\n", strerror(errno), __LINE__);
	return -1;
  }

  server = gethostbyname(host_name);
  if (server == NULL) {
    fprintf(stderr, "ERROR: %s, %d\n", strerror(errno), __LINE__);
    return -1;
  }

  bzero( ( char* ) &serv_addr, sizeof( serv_addr ) );
  serv_addr.sin_family = AF_INET;
  bcopy( ( char* )server->h_addr, ( char* ) &serv_addr.sin_addr.s_addr, server->h_length );
  serv_addr.sin_port = htons( portno );

  fcntl(fd, F_SETFL, O_NONBLOCK);

  rc = connect(fd, (struct sockaddr *) &serv_addr, sizeof( serv_addr));
  if ((rc == -1) && (errno != EINPROGRESS)) {
      fprintf(stderr, "ERROR: %s, %d\n", strerror(errno), __LINE__);
      close(fd);
      return -1;
  }

  FD_ZERO(&fdset);
  FD_SET(fd, &fdset);
  tv.tv_sec = NTP_TIMEOUT;
  tv.tv_usec = 0;

  rc = select(fd + 1, NULL, &fdset, NULL, &tv);
  if (rc == 0) {
      fprintf(stderr, "ERROR: %s, %d\n", strerror(so_error), __LINE__);
      close(fd);
      return -1;
  }

  len = sizeof(so_error);
  getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
  if (so_error != 0) {
    close(fd);
    fprintf(stderr, "ERROR: %s, %d\n", strerror(so_error), __LINE__);
    return -1;
  }

  fprintf(stderr, "Ready!\n");
  fcntl(fd, F_SETFL, 0);
  n = write(fd, (char*) &packet, sizeof(ntp_packet));
  if (n < 0) {
     close(fd);
     fprintf(stderr, "ERROR: %s, %d\n", strerror(errno), __LINE__);
     return -1;
  }

  fprintf(stderr, "ERROR: %d\n", __LINE__);
  n = read(fd, (char*) &packet, sizeof(ntp_packet));
  if (n < 0) {
     close(fd);
     fprintf(stderr, "ERROR: %s, %d\n", strerror(errno), __LINE__);
     return -1;
  }

  fprintf(stderr, "ERROR: %d\n", __LINE__);
  close(fd);
  packet.txTm_s = ntohl( packet.txTm_s ); // Time-stamp seconds.
  packet.txTm_f = ntohl( packet.txTm_f ); // Time-stamp fraction of a second.
  time_t txTm = ( time_t ) ( packet.txTm_s - NTP_TIMESTAMP_DELTA );
  printf("Time: %s\n", ctime((const time_t*) &txTm));
  time = 0;

  return 0;
}
