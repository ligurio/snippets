#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
 * TODO:
 * SNTP client: https://lettier.github.io/posts/2016-04-26-lets-make-a-ntp-client-in-c.html
 *
 * Simple Network Time Protocol (SNTP) Version 4 for IPv4, IPv6 and OSI
 * http://www.faqs.org/rfc/rfc4330.txt
 *
 */

enum better {
	LOWER,
	HIGHER
};

char* better_msg(enum better b) {

  switch(b) {
   case LOWER:
      return "lower-is-better";
      break;
   case HIGHER:
      return "higher-is-better";
      break;
   default:
      return "unknown";
  }
}

void print_stats(struct timespec tv0, const char *label, enum better b) {
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

  printf("%s,%ld.%.9ld,%s\n", label, (long)tv.tv_sec, (long)tv.tv_nsec, better_msg(b));
}

int run_bench(const char *label, size_t (*bench)(void *), void *params, enum better b) {

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
  print_stats(tv0, label, b);
  exit(0);
}

#define RUN(a, b, c)                                                           \
  extern size_t(a)(void *);                                                    \
  run_bench(#a " (" #b ")", (a), (b), (c))

int main() {

  printf("name,real_time,cpu_time,items_per_second,interpretation\n");

  RUN(b_malloc_sparse, 0, HIGHER);
  RUN(b_malloc_bubble, 0, HIGHER);
  RUN(b_malloc_tiny1, 0, HIGHER);
  RUN(b_malloc_tiny2, 0, HIGHER);
  RUN(b_malloc_big1, 0, HIGHER);
  RUN(b_malloc_big2, 0, HIGHER);
  RUN(b_malloc_thread_stress, 0, HIGHER);
  RUN(b_malloc_thread_local, 0, HIGHER);

  RUN(b_getifaddrs, 0, HIGHER);
  RUN(b_mmap, 0, HIGHER);
  RUN(b_fsync, 0, HIGHER);
  RUN(b_sigusr1, 0, HIGHER);
  RUN(b_sigignore, 0, HIGHER);
  RUN(b_syscall, 0, HIGHER);
#ifdef __LINUX__
  RUN(b_in, 0, HIGHER);
#endif
  RUN(b_cr8wr, 0, HIGHER);
  RUN(b_callret, 0, HIGHER);
  RUN(b_pgfault, 0, HIGHER);
  RUN(b_divzero, 0, HIGHER);
  RUN(b_ptemod, 0, HIGHER);
  RUN(b_cpuid, 0, HIGHER);
}
