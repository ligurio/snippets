/**
 * GCC (-finstrument-functions):
 *	- http://kernelchina.org/wp-content/uploads/2017/04/instrumental.pdf
 *  - https://linuxgazette.net/151/melinte.html
 *  - http://www.suse.de/~krahmer/instrumental/instrumental.tgz
 *
 * Clang:
 *  - http://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards
 *  - https://github.com/mcarpenter/afl/blob/master/llvm_mode/afl-clang-fast.c
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static int** cc_params;              /* parameters passed to the CC	*/
static int   cc_par_cnt = 1;         /* Param count, including argv0 */
static int   be_quiet,               /* Quiet mode                   */
            clang_mode;             /* Invoked as mapfunc-clang*?   */

static void make_params(int argc, char** argv) {

  u8 *name;
  cc_params = ck_alloc((argc + 128) * sizeof(u8*));

  name = strrchr(argv[0], '/');
  if (!name) name = argv[0]; else name++;

  if (!strncmp(name, "mapfunc-clang", 9)) {
    clang_mode = 1;
  }

  while (--argc) {
    u8* cur = *(++argv);
    cc_params[cc_par_cnt++] = cur;
  }

  cc_params[cc_par_cnt++] = "-B";
  cc_params[cc_par_cnt] = NULL;
}

int main(int argc, char** argv) {

  if (argc < 2) {
    printf("Usage");
    exit(1);
  }

  make_params(argc, argv);
  execvp(cc_params[0], (char**)cc_params);
  printf("Oops, failed to execute '%s' - check your PATH", cc_params[0]);
  return 0;
}
