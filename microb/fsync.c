/*
 *
 *  gcc -static -o fsync_test fsync_test.c -lrt -lm
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define B_SIZE 1024
#define B_NUM 10
#define MAX_FILES 100

extern int errno;

size_t b_fsync(void *dummy) {
  int fdo, i, j;
  char buffer[B_SIZE];

  srand(time(NULL));

  for (i = 0; i < MAX_FILES; i++) {

    for (j = 0; j < B_SIZE; j++) {
      buffer[j] = (char)(rand() & 0xFF);
    }

    char filename[] = "fsync-bench-XXXXXX";

    if ((fdo = mkstemp(filename)) == -1) {
      perror("mkstemp");
      return 1;
    }

    for (j = 0; j < B_NUM; j++) {
      if (write(fdo, buffer, sizeof(buffer)) == -1) {
        perror("write");
        return 1;
      }
    }

    if (fsync(fdo) == -1) {
      perror("fsync");
      return 1;
    }

    if (close(fdo) == -1) {
      perror("close");
      return 1;
    }
    unlink(filename);
  }

  return 0;
}
