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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>

#include "parse_subunit_v1.h"

const char *
directive_string(enum directive dir) {

	switch (dir) {
	case DIR_TEST:
		return "DIR_TEST";
	case DIR_SUCCESS:
		return "DIR_SUCCESS";
	case DIR_FAILURE:
		return "DIR_FAILURE";
	case DIR_ERROR:
		return "DIR_ERROR";
	case DIR_SKIP:
		return "DIR_SKIP";
	case DIR_XFAIL:
		return "DIR_XFAIL";
	case DIR_UXSUCCESS:
		return "DIR_UXSUCCESS";
	case DIR_PROGRESS:
		return "DIR_PROGRESS";
	case DIR_TAGS:
		return "DIR_TAGS";
	case DIR_TIME:
		return "DIR_TIME";
	default:
		return "DIR_UNKNOWN";
	}
}

enum directive
resolve_directive(char * string) {

	assert(string != (char*)NULL);

	if (strcasecmp(string, "test") == 0) {
		return DIR_TEST;
	} else if (strcasecmp(string, "testing") == 0) {
		return DIR_TEST;
	} else if (strcasecmp(string, "test:") == 0) {
		return DIR_TEST;
	} else if (strcasecmp(string, "testing:") == 0) {
		return DIR_TEST;
	} else if (strcasecmp(string, "success") == 0) {
		return DIR_SUCCESS;
	} else if (strcasecmp(string, "success:") == 0) {
		return DIR_SUCCESS;
	} else if (strcasecmp(string, "successful") == 0) {
		return DIR_SUCCESS;
	} else if (strcasecmp(string, "successful:") == 0) {
		return DIR_SUCCESS;
	} else if (strcasecmp(string, "failure") == 0) {
		return DIR_FAILURE;
	} else if (strcasecmp(string, "error") == 0) {
		return DIR_ERROR;
	} else if (strcasecmp(string, "skip") == 0) {
		return DIR_SKIP;
	} else if (strcasecmp(string, "xfail") == 0) {
		return DIR_XFAIL;
	} else if (strcasecmp(string, "uxsuccess") == 0) {
		return DIR_UXSUCCESS;
	} else if (strcasecmp(string, "progress:") == 0) {
		return DIR_PROGRESS;
	} else if (strcasecmp(string, "tags:") == 0) {
		return DIR_TAGS;
	} else if (strcasecmp(string, "time:") == 0) {
		return DIR_TIME;
	} else {
		return DIR_UNKNOWN;
	}
};

struct tm* parse_iso8601_time(char* date_str, char* time_str) {
	assert(date_str != (char*)NULL);
	assert(time_str != (char*)NULL);

	struct tm * t;
	t = malloc(sizeof(struct tm));
	if (t == NULL) {
		perror("failed to malloc");
		return NULL;
	}
	if (sscanf(date_str, "%d-%d-%d", &t->tm_year, &t->tm_mon, &t->tm_mday) == 3) {
		assert(t->tm_year > 2000);
		assert((t->tm_mon <= 12) && (t->tm_mon >= 0));
		assert((t->tm_mday <= 31) && (t->tm_mday >= 0));
	}

	if (sscanf(time_str, "%d:%d:%dZ", &t->tm_hour, &t->tm_min, &t->tm_sec) == 3) {
		assert((t->tm_hour <= 23) && (t->tm_hour >= 0));
		assert((t->tm_min <= 60) && (t->tm_min >= 0));
		assert((t->tm_sec <= 60) && (t->tm_sec >= 0));
	}

	return t;
};

void read_tok() {
	char* token;
	while (token != NULL) { token = strtok(NULL, " \t"); };
};

struct testline* parse_line_subunit_v1(char* string) {

	assert(string != (char*)NULL);

	char *dir, *token;
	struct testline *t;
	t = calloc(1, sizeof(struct testline));
	if (t == NULL) {
		perror("failed to malloc");
		return NULL;
	}

	char buffer[1024];
	strcpy(buffer, string);
	dir = strtok(buffer, " \t");

	enum directive d;
	switch (d = resolve_directive(dir)) {
	case DIR_TEST:
		t->dir = d;

		token = strtok(NULL, " \t");
		/* FIXME: assert(memcmp(token, "test", 4) != 0); */

		token = strtok(NULL, " \t");
		assert(token != NULL);
		t->label = token;

		token = strtok(NULL, " \t");
		assert(token == NULL);

		break;
	case DIR_SUCCESS:
		t->dir = d;

		token = strtok(NULL, " \t");
		/* FIXME: assert(memcmp(token, "test", 4) != 0); */

		token = strtok(NULL, " \t");
		assert(token != NULL);
		t->label = token;

		token = strtok(NULL, " \t");
		assert(token == NULL);

		break;
	case DIR_FAILURE:
		t->dir = d;
		token = strtok(NULL, " \t");
		/* FIXME: assert(memcmp(token, "test", 4) != 0); */

		token = strtok(NULL, " \t");
		assert(token != NULL);
		t->label = token;
		read_tok();

		break;
	case DIR_ERROR:
		t->dir = d;
		token = strtok(NULL, " \t");
		/* FIXME: assert(memcmp(token, "test", 4) != 0); */

		token = strtok(NULL, " \t");
		assert(token != NULL);
		t->label = token;
		read_tok();
		break;
	case DIR_SKIP:
		t->dir = d;
		token = strtok(NULL, " \t");
		/* FIXME: assert(memcmp(token, "test", 4) != 0); */

		token = strtok(NULL, " \t");
		assert(token != NULL);
		t->label = token;
		read_tok();
		break;
	case DIR_XFAIL:
		t->dir = d;
		token = strtok(NULL, " \t");
		/* FIXME: assert(memcmp(token, "test", 4) != 0); */

		token = strtok(NULL, " \t");
		assert(token != NULL);
		t->label = token;
		read_tok();
		break;
	case DIR_UXSUCCESS:
		t->dir = d;
		token = strtok(NULL, " \t");
		/* FIXME: assert(memcmp(token, "test", 4) != 0); */

		token = strtok(NULL, " \t");
		assert(token != NULL);
		t->label = token;
		read_tok();
		break;
	case DIR_PROGRESS:
		t->dir = d;
		read_tok();
		break;
	case DIR_TAGS:
		t->dir = d;
		while (token != NULL) {
			token = strtok(NULL, " \t");
			if (token != NULL) {
				printf("%s ", token);
			}
		};
		printf("\n");
		break;
	case DIR_TIME:
		t->dir = d;
		char *date, *time;
		date = strtok(NULL, " \t");
		time = strtok(NULL, " \t");
		struct tm *t = parse_iso8601_time(date, time);
		/* printf("Time: %s\n", asctime(t)); */
		read_tok();
		break;
	default:
		read_tok();
		return NULL;
	}

	return t;
};

struct suiteq* parse_subunit_v1(FILE *stream) {

	tailq_suite *suite_item;
	suite_item = (tailq_suite *) malloc(sizeof(tailq_suite));
	if (suite_item == NULL) {
		perror("malloc failed");
		return NULL;
	}
	/* TODO: n_errors, n_failures */
	suite_item->tests = calloc(1, sizeof(struct testq));
	if (suite_item->tests == NULL) {
		perror("malloc failed");
		free(suite_item);
		return NULL;
	};
	TAILQ_INIT(suite_item->tests);

	tailq_test *test_item = NULL;
	while (!feof(stream)) {
		test_item = NULL;
		TAILQ_INSERT_TAIL(suite_item->tests, test_item, entries);
	};

	struct suiteq *suites = NULL;
	suites = calloc(1, sizeof(struct suiteq));
	if (suites == NULL) {
		perror("malloc failed");
	};
	TAILQ_INIT(suites);
	TAILQ_INSERT_TAIL(suites, suite_item, entries);

	return suites;
};

int main() {

	char *path = "tests/samples/subunit/subunit-sample-04.subunit";
	FILE *file;
	/*
	file = fopen(path, O_RDONLY);
    	char line[1024];
    	while (fgets(line, sizeof(line), file)) {
            	printf("%s", line); 
		if (feof(file)) {
			break;
		}
    	}
    	fclose(file);
	*/

	char *test_sample[] = {
	"test test LABEL",
	"testing test LABEL",
	"test: test LABEL",
	"testing: test LABEL",
	"success test LABEL",
	"success: test LABEL",
	"successful test LABEL",
	"successful: test LABEL",
	"failure: test LABEL",
	"failure: test LABEL DETAILS",
	"error: test LABEL",
	"error: test LABEL DETAILS",
	"skip test LABEL",
	"skip: test LABEL",
	"skip test LABEL DETAILS",
	"skip: test LABEL DETAILS",
	"xfail test LABEL",
	"xfail: test LABEL",
	"xfail test LABEL DETAILS",
	"xfail: test LABEL DETAILS",
	"uxsuccess test LABEL",
	"uxsuccess: test LABEL",
	"uxsuccess test LABEL DETAILS",
	"uxsuccess: test LABEL DETAILS",
	"progress: +10",
	"progress: -14",
	"progress: push",
	"progress: pop",
	"tags: -small +big",
	"time: 2018-09-10 23:59:29Z" };

	char** qq = test_sample;
	struct testline* tl;
	for (int i = 0; i <  sizeof(test_sample)/sizeof(char*); ++i) {
		printf("(SOURCE LINE: %s) ", *qq);
		tl = parse_line_subunit_v1(*qq);
		if (tl != NULL) {
			printf("DIRECTIVE: %s, LABEL: %s", directive_string(tl->dir), tl->label);
		}
		printf("\n");
		++qq;
	}

	return 0;
};
