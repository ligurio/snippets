/*
 * Copyright © 2018 Sergey Bronnikov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

#ifndef PARSE_COMMON_H
#define PARSE_COMMON_H
#include "parse_common.h"
#endif /* PARSE_COMMON_H */

#include "ui_common.h"

void usage(char *name) {
  fprintf(stderr, "Usage: %s [-d directory] [-f file] [-h]\n", name);
}

int main(int argc, char *argv[]) {

  const char *storage_dir = "/";
  char *path = NULL;
  int opt = 0;

  while ((opt = getopt(argc, argv, "hd:f:")) != -1) {
      switch (opt) {
      case 'h':
          usage(argv[0]);
          return(1);
      case 'd':
          storage_dir = optarg;
          break;
      case 'f':
          path = optarg;
          break;
      default: /* '?' */
          usage(argv[0]);
          printf("hello\n");
          return 1;
      }
  }

  /*
  if (optind > argc) {
      usage(argv[0]);
      return 1;
  }
  */

  tailq_report *report_item;
  if (path != NULL) {
     report_item = process_file(path);
     /* FIXME: print_single_report(report_item); */
     return 0;
  }

  DIR *d;
  struct dirent *dir;
  d = opendir(storage_dir);
  if (d == NULL) {
      printf("failed to open dir %s\n", storage_dir);
      return 1;
  }


  tailq_report reportq;
  TAILQ_INIT(&reportq.head);

  while ((dir = readdir(d)) != NULL) {
      char *basename;
      basename = dir->d_name;
      if ((strcmp("..", basename) == 0) || (strcmp(".", basename) == 0)) {
         continue;
      }
      /* TODO: recursive search in directories */
      snprintf(path, 1024, "%s/%s", storage_dir, basename);
      report_item = process_file(path);
      TAILQ_INSERT_TAIL(&reportq.head, report_item, entries);
  }
  closedir(d);

  print_headers();
  /* FIXME: print_reports(&reportq); */

  /* Free the entire tail queue. */

  return 0;
}
