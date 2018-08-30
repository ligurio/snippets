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

#include "parse_common.h"
#include "ui_common.h"


int main(int argc, char *argv[]) {

  const char *storage_dir = "/";
  int opt = 0;

  while ((opt = getopt(argc, argv, "hd:")) != -1) {
      switch (opt) {
      case 'h':
          fprintf(stderr, "Usage: %s [-d directory] [-h]\n", argv[0]);
          return(1);
      case 'd':
          printf("%s\n", optarg);
          storage_dir = optarg;
          break;
      default: /* '?' */
          fprintf(stderr, "Usage: %s [-d directory] [-h]\n", argv[0]);
          return 1;
      }
  }

  /*
  if (optind >= argc) {
      fprintf(stderr, "Expected argument after options\n");
      return 1;
  }
  */

  printf("storage directory %s\n", storage_dir);

  DIR *d;
  struct dirent *dir;

  print_headers();

  d = opendir(storage_dir);
  if (!(d)) {
      printf("failed to open dir %s\n", storage_dir);
      return 1;
  }

  while ((dir = readdir(d)) != NULL) {
      char *basename;
      basename = dir->d_name;
      if ((strcmp("..", basename) == 0) || (strcmp(".", basename) == 0)) {
         continue;
      }
      /* TODO: check is it file or directory */
      process_file(storage_dir, basename);
  }
  closedir(d);

  return 0;
}
