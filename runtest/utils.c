#include <stdio.h>

#include <libgen.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>

#include "test_list.h"
#include "utils.h"

#define TIME_BUF_SIZE 1024
#define WAIT_CHILD_POLL_TIMEOUT_MS 200
#define WAIT_CHILD_BUF_MAX_SIZE 1024

static inline char *
format_time(char *strtime, size_t size)
{
	time_t t;
	struct tm *lt;

	t = time(NULL);
	lt = localtime(&t);
	strftime(strtime, size, "%Y-%m-%dT%H:%M", lt);

	return strtime;
}

struct test_list *
test_discovery(const char *dir)
{
	struct test_list *tests;
	struct stat st_buf;

	int n, i;
	struct dirent **namelist;
	int fail;
	int saved_errno;

	tests = calloc(1, sizeof(struct test_list));
	if (tests == NULL) {
		fprintf(stderr, "malloc failed");
		return NULL;
	}
	TAILQ_INIT(tests);

	do
	{
		if (stat(dir, &st_buf) == -1) {
			free_tests(tests);
			break;
		}

		if (!S_ISDIR(st_buf.st_mode)) {
			free_tests(tests);
			errno = EINVAL;
			break;
		}

		n = scandir(dir, &namelist, NULL, alphasort);
		if (n == -1) {
			free_tests(tests);
			break;
		}

		fail = 0;
		for (i = 0; i < n; i++) {
			char *run_test;
			char *d_name = strdup(namelist[i]->d_name);
			if (d_name == NULL) {
				fail = 1;
				saved_errno = errno;
				break;
			}

			if (strcmp(d_name, ".") == 0 ||
			    strcmp(d_name, "..") == 0) {
				free(d_name);
				continue;
			}

			printf("%s\n", d_name);
			if (asprintf(&run_test, "%s/%s/runtest",
			    dir, d_name) == -1)  {
				fail = 1;
				saved_errno = errno;
				free(d_name);
				break;
			}

			if (stat(run_test, &st_buf) == -1) {
				free(run_test);
				free(d_name);
				continue;
			}

			if (!S_ISREG(st_buf.st_mode)) {
				free(run_test);
				free(d_name);
				continue;
			}

/*
			if (test_list_search_by_file(head, run_test, st_buf)) {
				free(run_test);
				free(d_name);
				continue;
			}

*/

/*
			struct test_list *p = test_list_add(head,
				d_name, run_test);
			if (p == NULL) {
				fail = 1;
				saved_errno = errno;
				free(run_test);
				free(d_name);
				break;
			}
*/
			struct test *t = NULL;
			t= calloc(1, sizeof(struct test));
			if (t == NULL) {
				fprintf(stderr, "malloc failed");
				break;
			}
			t->name = run_test;
			t->path = d_name;
			TAILQ_INSERT_TAIL(tests, t, entries);
		}

		for (i = 0 ; i < n; i++)
			free(namelist[i]);
		free(namelist);

		if (fail) {
			free_tests(tests);
			errno = saved_errno;
			break;
		}
	} while (0);

	return tests;
}

int
print_tests(struct test_list *tests, FILE *fp)
{
	if (tests == NULL || test_list_length(tests) <= 0) {
		fprintf(fp, MSG_TESTS_NOT_FOUND);
		return 1;
	} else {
		fprintf(fp, MSG_TESTS_AVAILABLE);
		struct test *t;
		TAILQ_FOREACH(t, tests, entries) {
			fprintf(fp, "%s\n", t->name);
		}

		return 0;
	}
}

/*
struct test_list *
filter_tests(struct test_list *head, char **tests, int test_num)
{
	struct test_list *head_new = NULL, *n;
	int fail = 0, i, saved_errno;

	do {
		if (head == NULL || tests == NULL || test_num <= 0) {
			errno = EINVAL;
			break;
		}

		head_new = test_list_alloc();
		if (head_new == NULL)
			break;

		for (i = 0; i < test_num; i++) {
			char *test;
			char *run_test;

			n = test_list_search(head, tests[i]);
			if (n == NULL) {
				saved_errno = errno;
				fail = 1;
				break;
			}

			test = strdup(n->test);
			run_test = strdup(n->run_test);
			if (test == NULL || run_test == NULL) {
				saved_errno = errno;
				fail = 1;
				break;
			}

			if (test_list_add(head_new, test, run_test) == NULL) {
				saved_errno = errno;
				fail = 1;
				break;
			}
		}

		if (fail) {
			TEST_LIST_FREE_ALL_CLEAN(head_new);
			errno = saved_errno;
		}
	} while (0);

	return head_new;
}
*/

static inline void
run_child(char *run_test, int fd_stdout, int fd_stderr)
{
	char **argv = malloc(sizeof(char) * 2);
	chdir(dirname(strdup(run_test)));

	argv[0] = run_test;
	argv[1] = NULL;

	dup2(fd_stdout, STDOUT_FILENO);
	dup2(fd_stderr, STDERR_FILENO);
	execv(run_test, argv);

	exit(1);
}

static inline int
wait_child(const char *test_dir, const char *run_test, pid_t pid,
		int timeout, int *fds, FILE **fps)
{
	struct pollfd pfds[2];
	struct timespec sentinel;
	clockid_t clock = CLOCK_MONOTONIC;
	int r;

	int timeouted = 0;
	int status;
	int waitflags;

	pfds[0].fd = fds[0];
	pfds[0].events = POLLIN;
	pfds[1].fd = fds[1];
	pfds[1].events = POLLIN;

	if (clock_gettime(clock, &sentinel) == -1) {
		clock = CLOCK_REALTIME;
		clock_gettime(clock, &sentinel);
	}

	while (1) {
		waitflags = WNOHANG;

		r = poll(pfds, 2, WAIT_CHILD_POLL_TIMEOUT_MS);
		if (r > 0) {
			char buf[WAIT_CHILD_BUF_MAX_SIZE];
			ssize_t n;

			if (pfds[0].revents != 0) {
				while ((n = read(fds[0], buf, WAIT_CHILD_BUF_MAX_SIZE)) > 0)
					fwrite(buf, n, 1, fps[0]);
			}

			if (pfds[1].revents != 0) {
				while ((n = read(fds[1], buf, WAIT_CHILD_BUF_MAX_SIZE)) > 0)
					fwrite(buf, n, 1, fps[1]);
			}

			clock_gettime(clock, &sentinel);
		} else if (timeout >= 0) {
			struct timespec time;

			clock_gettime(clock, &time);
			if ((time.tv_sec - sentinel.tv_sec) > timeout) {
				timeouted = 1;
				kill(pid, SIGKILL);
				waitflags = 0;
			}
		}

		if (waitpid(pid, &status, waitflags) == pid)
			break;
	}

	if (status) {
		fprintf(fps[0], "\nERROR: Exit status is %d\n", status);
		if (timeouted)
			fprintf(fps[0], "TIMEOUT: %s\n", test_dir);
	}

	return status;
}

int
run_tests(struct test_list *tests, const struct test_options opts,
		const char *progname, FILE *fp, FILE *fp_stderr)
{
	int rc = 0;
	char time[TIME_BUF_SIZE];

	pid_t child;
	int pipefd_stdout[2];
	int pipefd_stderr[2];

	do
	{
		if ((rc = pipe2(pipefd_stdout, O_NONBLOCK)) == -1)
			break;

		if ((rc = pipe2(pipefd_stderr, O_NONBLOCK)) == -1) {
			close(pipefd_stdout[0]);
			close(pipefd_stdout[1]);
			break;
		}

		fprintf(fp, "START: %s\n", progname);
		struct test *t;
		TAILQ_FOREACH(t, tests, entries) {
			char *test_dir = strdup(t->name);
			if (test_dir == NULL) {
				rc = -1;
				break;
			}
			dirname(test_dir);

			child = fork();
			if (child == -1) {
				fprintf(fp, "ERROR: Fork %s\n", strerror(errno));
				rc = -1;
				break;
			} else if (child == 0) {
				run_child(t->name, pipefd_stdout[1], pipefd_stderr[1]);
			} else {
				int status;
				int fds[2]; fds[0] = pipefd_stdout[0]; fds[1] = pipefd_stderr[0];
				FILE *fps[2]; fps[0] = fp; fps[1] = fp_stderr;

				fprintf(fp, "%s\n", format_time(time, TIME_BUF_SIZE));
				fprintf(fp, "BEGIN: %s\n", test_dir);

				status = wait_child(test_dir, t->name, child,
						opts.timeout, fds, fps);
				if (status)
					rc += 1;

				fprintf(fp, "END: %s\n", test_dir);
				fprintf(fp, "%s\n", format_time(time, TIME_BUF_SIZE));
			}
		}
		fprintf(fp, "STOP: %s\n", progname);

		close(pipefd_stdout[0]); close(pipefd_stdout[1]);
		close(pipefd_stderr[0]); close(pipefd_stderr[1]);
	} while (0);

	if (rc == -1)
		fprintf(fp_stderr, "run_tests fails: %s", strerror(errno));

	return rc;
}

int test_list_length(struct test_list *tests) {
	int num = 0;
	struct test *t;
	TAILQ_FOREACH(t, tests, entries) {
	    num++;
	}
	return num;
}