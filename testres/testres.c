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
#include <fcntl.h>
#include <err.h>

#include "parse_junit.h"
#include "parse_testanything.h"

char *get_filename_ext(const char *filename) {
    char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return "";

    return dot + 1;
}

void print_headers() {
  printf("Content-Type: text/plain;charset=utf-8\n\n");
}

void usage() {
  printf("testres\n");
  printf("\tUsage: testres -d DIR\n");
}

int main(int argc, char *argv[]) {

  char *storage_dir = "/";
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

  printf("storage directory %s", storage_dir);

  DIR *d;
  struct dirent *dir;
  char *d_name, *file_ext;

  print_headers();

  d = opendir(storage_dir);
  if (!(d)) {
    printf("failed to open dir %s", storage_dir);
    return 1;
  }

  while ((dir = readdir(d)) != NULL) {
    d_name = dir->d_name;
    if ((strcmp("..", d_name) == 0) || (strcmp(".", d_name) == 0)) {
       continue;
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", storage_dir, d_name);
    printf("%s\n", path);

    FILE *file;
    file = fopen(path, "r");
    if (!(file)) {
       printf("failed to open file %s", path);
       return 1;
    }
    file_ext = get_filename_ext(d_name);
    printf("extension %s\n", file_ext);
    if (strcasecmp("xml", file_ext) == 0) {
       printf("JUnit %s\n", d_name);
       parse_junit(file);
       continue;
    }
    if (strcasecmp("tap", file_ext) == 0) {
       printf("TestAnythingProtocol %s\n", d_name);
       struct ast_test *tests;
       tests = parse_testanything(file);
       print(stdout, tests);
       continue;
    }
    if (strcasecmp("subunit", file_ext) == 0) {
       printf("SubUnit %s\n", d_name);
       printf("TODO\n");
       continue;
    }
    fclose(file);
  }
  closedir(d);
  return(0);
}
