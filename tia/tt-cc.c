/**
 * GCC (-finstrument-functions):
 *  - http://kernelchina.org/wp-content/uploads/2017/04/instrumental.pdf
 *  - https://linuxgazette.net/151/melinte.html
 *  - http://www.suse.de/~krahmer/instrumental/instrumental.tgz
 *
 * Clang:
 *  - http://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards
 *  - https://github.com/mcarpenter/afl/blob/master/llvm_mode/afl-clang-fast.c
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int clang_mode = 0, gcc_mode = 0;
static uint8_t** cc_params;
static uint32_t cc_par_cnt = 1;

static void make_params(int argc, char** argv) {

  char *name;
  cc_params = malloc((argc + 128) * sizeof(char));

  name = strrchr(argv[0], '/');
  if (!name) name = argv[0]; else name++;

  if (!strncmp(name, "tt-clang", 9)) {
     clang_mode = 1;
  }

  if (!strcmp(name, "tt-clang++")) {
    cc_params[0] = (uint8_t*)"clang++";
  } else {
    cc_params[0] = (uint8_t*)"clang";
  }

  if (!strncmp(name, "tt-gcc", 7)) {
     gcc_mode = 1;
  }

  while (--argc) {
     uint8_t *cur = (uint8_t*)*(++argv);
     cc_params[cc_par_cnt++] = cur;
  }

  if (clang_mode == 1) {
	 /* cc_params[cc_par_cnt++] = (uint8_t*)("-fsanitize-coverage=trace-pc"); */
	 cc_params[cc_par_cnt++] = (uint8_t*)("-Xclang");
	 cc_params[cc_par_cnt++] = (uint8_t*)("-ast-dump");
	 cc_params[cc_par_cnt++] = (uint8_t*)("-fsyntax-only");
  }

  if (gcc_mode == 1) {
	 cc_params[cc_par_cnt++] = (uint8_t*)"-finstrument-functions";
	 cc_params[cc_par_cnt++] = (uint8_t*)"-fno-inline-functions";
	 cc_params[cc_par_cnt++] = (uint8_t*)"-fno-inline-functions-called-once";
	 cc_params[cc_par_cnt++] = (uint8_t*)"-fno-optimize-sibling-calls";
	 cc_params[cc_par_cnt++] = (uint8_t*)"-fno-default-inline";
	 cc_params[cc_par_cnt++] = (uint8_t*)"-fno-inline";
     /* gcc -fdump-tree-all-graph -g hello_world.c */
  }

  cc_params[cc_par_cnt++] = (uint8_t*)"-g3";
  cc_params[cc_par_cnt++] = (uint8_t*)"-fno-omit-frame-pointer";
  cc_params[cc_par_cnt++] = (uint8_t*)"-O2";
  cc_params[cc_par_cnt++] = (uint8_t*)"-DNDEBUG";
  /* gprof */
  cc_params[cc_par_cnt++] = (uint8_t*)"-pg";
  cc_params[cc_par_cnt] = NULL;
}

int main(int argc, char** argv) {

  if (argc < 2) {
     printf("Usage\n");
     exit(1);
  }

  make_params(argc, argv);
  execvp((const char*)cc_params[0], (char**)cc_params);

  return 0;
}
