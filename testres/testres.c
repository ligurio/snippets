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

  const char *path_dir = (char*)NULL;
  char *path_file = (char*)NULL;
  int opt = 0;

  while ((opt = getopt(argc, argv, "hd:f:")) != -1) {
      switch (opt) {
      case 'h':
          usage(argv[0]);
          return(1);
      case 'd':
          path_dir = optarg;
          break;
      case 'f':
          path_file = optarg;
          break;
      default: /* '?' */
          usage(argv[0]);
          return 1;
      }
  }

  if (argc == 1) {
      usage(argv[0]);
      return 1;
  }

  tailq_report *report_item;
  if (path_file != NULL) {
     report_item = process_file(path_file);
     print_single_report(report_item);
     free_single_report(report_item);
     return 0;
  }

  DIR *d;
  struct dirent *dir;
  d = opendir(path_dir);
  if (d == NULL) {
     printf("failed to open dir %s\n", path_dir);
     return 1;
  }

  struct reportq reports;
  TAILQ_INIT(&reports);

  while ((dir = readdir(d)) != NULL) {
      char *basename;
      basename = dir->d_name;
      if ((strcmp("..", basename) == 0) || (strcmp(".", basename) == 0)) {
         continue;
      }
      /* TODO: recursive search in directories */
      int path_len = strlen(path_dir) + strlen(basename) + 2;
      path_file = malloc(path_len);
      snprintf(path_file, path_len, "%s/%s", path_dir, basename);
      report_item = process_file(path_file);
      TAILQ_INSERT_TAIL(&reports, report_item, entries);
      free(path_file);
  }
  closedir(d);

  print_headers();
  print_reports(&reports);
  free_reports(&reports);

  return 0;
}
