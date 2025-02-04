#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

/*
 * This code will query a ntp server for the local time and display it.
 *
 * https://lettier.github.io/posts/2016-04-26-lets-make-a-ntp-client-in-c.html
 *
 * Simple Network Time Protocol (SNTP) Version 4 for IPv4, IPv6 and OSI
 * http://www.faqs.org/rfc/rfc4330.txt
 *
 */

#define NTP_TIMESTAMP_DELTA 2208988800ull

int gettime(void);

int gettime(void) {

  int sockfd, n;
  int portno = 123;
  char *host_name = "us.pool.ntp.org";

  typedef struct {

    unsigned li : 2; // Only two bits. Leap indicator.
    unsigned vn : 3; // Only three bits. Version number of the protocol.
    unsigned
        mode : 3; // Only three bits. Mode. Client will pick mode 3 for client.

    uint8_t stratum; // Eight bits. Stratum level of the local clock.
    uint8_t poll; // Eight bits. Maximum interval between successive messages.
    uint8_t precision; // Eight bits. Precision of the local clock.

    uint32_t rootDelay; // 32 bits. Total round trip delay time.
    uint32_t
        rootDispersion; // 32 bits. Max error aloud from primary clock source.
    uint32_t refId;     // 32 bits. Reference clock identifier.

    uint32_t refTm_s; // 32 bits. Reference time-stamp seconds.
    uint32_t refTm_f; // 32 bits. Reference time-stamp fraction of a second.

    uint32_t origTm_s; // 32 bits. Originate time-stamp seconds.
    uint32_t origTm_f; // 32 bits. Originate time-stamp fraction of a second.

    uint32_t rxTm_s; // 32 bits. Received time-stamp seconds.
    uint32_t rxTm_f; // 32 bits. Received time-stamp fraction of a second.

    uint32_t txTm_s; // 32 bits and the most important field the client cares
                     // about. Transmit time-stamp seconds.
    uint32_t txTm_f; // 32 bits. Transmit time-stamp fraction of a second.

  } ntp_packet; // Total: 384 bits or 48 bytes.

  ntp_packet packet = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  memset(&packet, 0, sizeof(ntp_packet));

  // Set the first byte's bits to 00,011,011 for li = 0, vn = 3, and mode = 3.
  // The rest will be left set to zero.

  *((char *)&packet + 0) =
      0x1b; // Represents 27 in base 10 or 00011011 in base 2.

  // Create a UDP socket, convert the host-name to an IP address, set the port
  // number, connect to the server, send the packet, and then read in the return
  // packet.

  struct sockaddr_in serv_addr;
  struct hostent *server;

  sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (sockfd < 0)
    perror("ERROR opening socket");
  exit(1);

  server = gethostbyname(host_name);

  if (server == NULL)
    perror("ERROR, no such host");
  exit(1);

  bzero((char *)&serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr,
        server->h_length);
  serv_addr.sin_port = htons(portno);

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    perror("ERROR connecting");
  exit(1);

  n = write(sockfd, (char *)&packet, sizeof(ntp_packet));
  if (n < 0)
    perror("ERROR writing to socket");
  exit(1);

  n = read(sockfd, (char *)&packet, sizeof(ntp_packet));
  if (n < 0)
    perror("ERROR reading from socket");
  exit(1);

  // These two fields contain the time-stamp seconds as the packet left the NTP
  // server. The number of seconds correspond to the seconds passed since 1900.
  // ntohl() converts the bit/byte order from the network's to host's
  // "endianness".

  packet.txTm_s = ntohl(packet.txTm_s); // Time-stamp seconds.
  packet.txTm_f = ntohl(packet.txTm_f); // Time-stamp fraction of a second.

  /*
   * Extract the 32 bits that represent the time-stamp seconds (since NTP
   * epoch) from when the packet left the server.
   * Subtract 70 years worth of seconds from the seconds since 1900.
   * This leaves the seconds since the UNIX epoch of 1970.
   *
   * Convert time to unix standard time NTP is number of seconds since 0000
   * UT on 1 January 1900 unix time is seconds since 0000 UT on 1 January
   * 1970 There has been a trend to add a 2 leap seconds every 3 years.
   * Leap seconds are only an issue the last second of the month in June and
   * December if you don't try to set the clock then it can be ignored but
   * this is importaint to people who coordinate times with GPS clock sources.
   */

  time_t txTm = (time_t)(packet.txTm_s - NTP_TIMESTAMP_DELTA);
  printf("Time: %s", ctime((const time_t *)txTm));

  return 0;
}

void print_stats(struct timespec tv0, const char *label) {
  struct timespec tv;

#ifdef __LINUX__
  clock_gettime(CLOCK_MONOTONIC_RAW, &tv);
#else
  clock_gettime(CLOCK_MONOTONIC, &tv);
#endif
  tv.tv_sec -= tv0.tv_sec;
  if ((tv.tv_nsec -= tv0.tv_nsec) < 0) {
    tv.tv_nsec += 1000000000;
    tv.tv_sec--;
  }

  printf("%s,%ld.%.9ld\n", label, (long)tv.tv_sec, (long)tv.tv_nsec);
}

int run_bench(const char *label, size_t (*bench)(void *), void *params) {
  struct timespec tv0;
  pid_t p = fork();
  if (p) {
    int status;
    wait(&status);
    return status;
  }

#ifdef __LINUX__
  clock_gettime(CLOCK_MONOTONIC_RAW, &tv0);
#else
  clock_gettime(CLOCK_MONOTONIC, &tv0);
#endif
  bench(params);
  print_stats(tv0, label);
  exit(0);
}

#define RUN(a, b)                                                              \
  extern size_t(a)(void *);                                                    \
  run_bench(#a " (" #b ")", (a), (b))

int main() {

  printf("name,real_time,cpu_time,items_per_second\n");

  RUN(b_malloc_sparse, 0);
  RUN(b_malloc_bubble, 0);
  RUN(b_malloc_tiny1, 0);
  RUN(b_malloc_tiny2, 0);
  RUN(b_malloc_big1, 0);
  RUN(b_malloc_big2, 0);
  RUN(b_malloc_thread_stress, 0);
  RUN(b_malloc_thread_local, 0);

  RUN(b_getifaddrs, 0);
  RUN(b_mmap, 0);
  RUN(b_fsync, 0);
  RUN(b_sigusr1, 0);
  RUN(b_sigignore, 0);
  RUN(b_syscall, 0);
#ifdef __LINUX__
  RUN(b_in, 0);
#endif
  RUN(b_cr8wr, 0);
  RUN(b_callret, 0);
  RUN(b_pgfault, 0);
  RUN(b_divzero, 0);
  RUN(b_ptemod, 0);
  RUN(b_cpuid, 0);
}
