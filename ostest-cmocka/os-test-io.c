/*  gcc os-test-io.c -o os-test -I/usr/local/include -L/usr/local/lib -lcmocka */

#ifdef __HAIKU__
#define _BSD_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

/* Open a temporary file for reading as a directory, testing whether the open
   succeeds. */
static void open_mkstemp_rdonly_directory(void **state) {
    (void) state;
#ifdef O_DIRECTORY
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	const char* template = "open-mkstemp-rdonly.XXXXXX";
	size_t path_size = strlen(tmpdir) + 1 + strlen(template) + 1;
	char* path = malloc(path_size);
	if ( !path )
		err(1, "malloc");
	snprintf(path, path_size, "%s/%s", tmpdir, template);
	int tmp_fd = mkstemp(path);
	if ( tmp_fd < 0 )
		err(1, "mkstemp");
	int fd = open(path, O_RDONLY | O_DIRECTORY);
	if ( fd < 0 )
	{
		unlink(path);
		err(1, "open");
	}
	unlink(path);
	return 0;
#else
	errx(1, "O_DIRECTORY is not defined");
#endif
}

/* Open a temporary file for reading and truncation as a directory, testing
   whether the open succeeds and whether the file was truncated. */

int open_mkstemp_rdonly_trunc_directory(void)
{
#ifdef O_DIRECTORY
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	const char* template = "open-mkstemp-rdonly.XXXXXX";
	size_t path_size = strlen(tmpdir) + 1 + strlen(template) + 1;
	char* path = malloc(path_size);
	if ( !path )
		err(1, "malloc");
	snprintf(path, path_size, "%s/%s", tmpdir, template);
	int tmp_fd = mkstemp(path);
	if ( tmp_fd < 0 )
		err(1, "mkstemp");
	char x = 'x';
	if ( write(tmp_fd, &x, 1) < 0 )
		err(1, "write");
	int fd = open(path, O_RDONLY | O_TRUNC | O_DIRECTORY);
	off_t size = lseek(tmp_fd, 0, SEEK_END);
	if ( size != 1 )
		printf("file was truncated\n");
	if ( fd < 0 )
	{
		unlink(path);
		err(1, "open");
	}
	unlink(path);
	return 0;
#else
	errx(1, "O_DIRECTORY is not defined");
#endif
}

/* Open a temporary file for reading and truncation, testing whether there are
   any unintended truncation. */
int open_mkstemp_rdonly_trunc(void)
{
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	const char* template = "open-mkstemp-rdonly.XXXXXX";
	size_t path_size = strlen(tmpdir) + 1 + strlen(template) + 1;
	char* path = malloc(path_size);
	if ( !path )
		err(1, "malloc");
	snprintf(path, path_size, "%s/%s", tmpdir, template);
	int tmp_fd = mkstemp(path);
	if ( tmp_fd < 0 )
		err(1, "mkstemp");
	char x = 'x';
	if ( write(tmp_fd, &x, 1) < 0 )
		err(1, "write");
	int fd = open(path, O_RDONLY | O_TRUNC);
	off_t size = lseek(tmp_fd, 0, SEEK_END);
	if ( size != 1 )
		printf("file was truncated\n");
	if ( fd < 0 )
	{
		unlink(path);
		err(1, "open");
	}
	unlink(path);
	return 0;
}

/* Open a temporary file for reading. */
int open_mkstemp_rdonly(void)
{
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	const char* template = "open-mkstemp-rdonly.XXXXXX";
	size_t path_size = strlen(tmpdir) + 1 + strlen(template) + 1;
	char* path = malloc(path_size);
	if ( !path )
		err(1, "malloc");
	snprintf(path, path_size, "%s/%s", tmpdir, template);
	int tmp_fd = mkstemp(path);
	if ( tmp_fd < 0 )
		err(1, "mkstemp");
	int fd = open(path, O_RDONLY);
	if ( fd < 0 )
	{
		unlink(path);
		err(1, "open");
	}
	unlink(path);
	return 0;
}

/* Open a temporary file for writing as a directory, testing whether the open
   succeeds. */
int open_mkstemp_wronly_directory(void)
{
#ifdef O_DIRECTORY
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	const char* template = "open-mkstemp-rdonly.XXXXXX";
	size_t path_size = strlen(tmpdir) + 1 + strlen(template) + 1;
	char* path = malloc(path_size);
	if ( !path )
		err(1, "malloc");
	snprintf(path, path_size, "%s/%s", tmpdir, template);
	int tmp_fd = mkstemp(path);
	if ( tmp_fd < 0 )
		err(1, "mkstemp");
	int fd = open(path, O_WRONLY | O_DIRECTORY);
	if ( fd < 0 )
	{
		unlink(path);
		err(1, "open");
	}
	unlink(path);
	return 0;
#else
	errx(1, "O_DIRECTORY is not defined");
#endif
}

/* Open a temporary file for writing and truncation as a directory, testing
   whether the open succeeds and whether the file was truncated. */
int open_mkstemp_wronly_trunc_directory(void)
{
#ifdef O_DIRECTORY
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	const char* template = "open-mkstemp-rdonly.XXXXXX";
	size_t path_size = strlen(tmpdir) + 1 + strlen(template) + 1;
	char* path = malloc(path_size);
	if ( !path )
		err(1, "malloc");
	snprintf(path, path_size, "%s/%s", tmpdir, template);
	int tmp_fd = mkstemp(path);
	if ( tmp_fd < 0 )
		err(1, "mkstemp");
	char x = 'x';
	if ( write(tmp_fd, &x, 1) < 0 )
		err(1, "write");
	int fd = open(path, O_WRONLY | O_TRUNC | O_DIRECTORY);
	off_t size = lseek(tmp_fd, 0, SEEK_END);
	if ( size != 1 )
		printf("file was truncated\n");
	if ( fd < 0 )
	{
		unlink(path);
		err(1, "open");
	}
	unlink(path);
	return 0;
#else
	errx(1, "O_DIRECTORY is not defined");
#endif
}

/* Open TMPDIR for reading and appending. */
int open_tmpdir_rdonly_append(void)
{
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd = open(tmpdir, O_RDONLY | O_APPEND);
	if ( fd < 0 )
		err(1, "open");
	return 0;
}

/* Open TMPDIR for reading and creation. */
int open_tmpdir_rdonly_creat(void)
{
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd = open(tmpdir, O_RDONLY | O_CREAT, 0777);
	if ( fd < 0 )
		err(1, "open");
	return 0;
}

/* Open TMPDIR for reading as a directory. */
int open_tmpdir_rdonly_directory(void)
{
#ifdef O_DIRECTORY
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd = open(tmpdir, O_RDONLY | O_DIRECTORY);
	if ( fd < 0 )
		err(1, "open");
	return 0;
#else
	errx(1, "O_DIRECTORY is not defined");
#endif
}

/* Open TMPDIR for reading and truncation. */
int open_tmpdir_rdonly_trunc(void)
{
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd = open(tmpdir, O_RDONLY | O_TRUNC);
	if ( fd < 0 )
		err(1, "open");
	return 0;
}

/* Open TMPDIR for reading. */
int open_tmpdir_rdonly(void)
{
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd = open(tmpdir, O_RDONLY);
	if ( fd < 0 )
		err(1, "open");
	return 0;
}

/* Open TMPDIR for reading, writing, and appending. */
int open_tmpdir_rdwr_append(void)
{
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd = open(tmpdir, O_RDWR | O_APPEND);
	if ( fd < 0 )
		err(1, "open");
	return 0;
}

/* Open TMPDIR for reading, writing, and creation. */
int open_tmpdir_rdwr_creat(void)
{
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd = open(tmpdir, O_RDWR | O_CREAT, 0777);
	if ( fd < 0 )
		err(1, "open");
	return 0;
}

/* Open TMPDIR for reading and writing as a directory. */
int open_tmpdir_rdwr_directory(void)
{
#ifdef O_DIRECTORY
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd = open(tmpdir, O_RDWR | O_DIRECTORY);
	if ( fd < 0 )
		err(1, "open");
	return 0;
#else
	errx(1, "O_DIRECTORY is not defined");
#endif
}

/* Open TMPDIR for reading, writing, and truncation. */
int open_tmpdir_rdwr_trunc(void)
{
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd = open(tmpdir, O_RDWR | O_TRUNC);
	if ( fd < 0 )
		err(1, "open");
	return 0;
}

/* Open TMPDIR for reading and writing. */
int open_tmpdir_rdwr(void)
{
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd = open(tmpdir, O_RDWR);
	if ( fd < 0 )
		err(1, "open");
	return 0;
}

/* Open TMPDIR for writing and appending. */
int open_tmpdir_wronly_append(void)
{
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd = open(tmpdir, O_WRONLY | O_APPEND);
	if ( fd < 0 )
		err(1, "open");
	return 0;
}

/* Open TMPDIR for writing and creation. */
int open_tmpdir_wronly_creat(void)
{
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd = open(tmpdir, O_WRONLY | O_CREAT, 0777);
	if ( fd < 0 )
		err(1, "open");
	return 0;
}

/* Open TMPDIR for writing as a directory. */
int open_tmpdir_wronly_directory(void)
{
#ifdef O_DIRECTORY
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd = open(tmpdir, O_WRONLY | O_DIRECTORY);
	if ( fd < 0 )
		err(1, "open");
	return 0;
#else
	errx(1, "O_DIRECTORY is not defined");
#endif
}

/* Open TMPDIR for writing and truncation. */
int open_tmpdir_wronly_trunc(void)
{
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd = open(tmpdir, O_WRONLY | O_TRUNC);
	if ( fd < 0 )
		err(1, "open");
	return 0;
}

/* Open TMPDIR for writing. */
int open_tmpdir_wronly(void)
{
	const char* tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd = open(tmpdir, O_WRONLY);
	if ( fd < 0 )
		err(1, "open");
	return 0;
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(open_mkstemp_rdonly_directory),
        cmocka_unit_test(open_mkstemp_rdonly_trunc_directory),
        cmocka_unit_test(open_mkstemp_rdonly_trunc),
        cmocka_unit_test(open_mkstemp_rdonly),
        cmocka_unit_test(open_mkstemp_wronly_directory),
        cmocka_unit_test(open_mkstemp_wronly_trunc_directory),
        cmocka_unit_test(open_tmpdir_rdonly_append),
        cmocka_unit_test(open_tmpdir_rdonly_creat),
        cmocka_unit_test(open_tmpdir_rdonly_directory),
        cmocka_unit_test(open_tmpdir_rdonly_trunc),
        cmocka_unit_test(open_tmpdir_rdonly),
        cmocka_unit_test(open_tmpdir_rdwr_append),
        cmocka_unit_test(open_tmpdir_rdwr_creat),
        cmocka_unit_test(open_tmpdir_rdwr_directory),
        cmocka_unit_test(open_tmpdir_rdwr_trunc),
        cmocka_unit_test(open_tmpdir_rdwr),
        cmocka_unit_test(open_tmpdir_wronly_append),
        cmocka_unit_test(open_tmpdir_wronly_creat),
        cmocka_unit_test(open_tmpdir_wronly_directory),
        cmocka_unit_test(open_tmpdir_wronly_trunc),
        cmocka_unit_test(open_tmpdir_wronly),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
