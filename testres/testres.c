#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>

#include "parse_junit.h"

char *get_filename_ext(const char *filename) {
    char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return "";

    return dot + 1;
}

void print_headers() {
  printf("Content-Type: text/plain;charset=utf-8\n\n");
}

void usage() {
  printf("testres\n\n");
  printf("Usage: testres -d DIR");
}

int main(int argc, char *argv[]) {

  const char *REPORTS = "/htdocs/junit/";

/*
  int bflag, ch, fd;
  bflag = 0;
  while ((ch = getopt(argc, argv, "bd:")) != -1) {
   	   switch (ch) {
   	   case 'd':
			   printf("%s\n", optarg);
   			   break;
   	   default:
   			   usage();
   	   }
  }
  argc -= optind;
  argv += optind;


int
main(int argc, char *argv[])
{
	struct ast_test *tests;
	int a, b;
	int fold;

	fold = 0;

	{
		int c;

		while (c = getopt(argc, argv, "dh"), c != -1) {
			switch (c) {
			case 'd': fold = 1; break;

			case 'h':
				usage();
				return 0;

			default:
				usage();
				return 1;
			}
		}

		argc -= optind;
		argv += optind;
	}

	if (argc != 0) {
		usage();
		return 1;
	}
}
*/

  DIR *d;
  struct dirent *dir;
  char *d_name, *file_ext;

  print_headers();

  d = opendir(REPORTS);
  if (d) {
    while ((dir = readdir(d)) != NULL) {
      d_name = dir->d_name;
      if ((strcmp("..", d_name) == 0) || (strcmp(".", d_name) == 0)) {
         continue;
      }
      file_ext = get_filename_ext(d_name);
      if (strcmp("xml", file_ext)) {
         continue;
      }
      printf("%s\n", d_name);
	  char path[1024];
	  snprintf(path, sizeof(path), "%s/%s", REPORTS, d_name);
	  printf("%s", path);
      parse_junit(path);
    }
    closedir(d);
  }
  return(0);
}
