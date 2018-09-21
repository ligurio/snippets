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

#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <unistd.h>

#include "deviation.h"

void
usage(char *path)
{
	char *name = basename(path);
	fprintf(stderr, "Usage: %s [-h|-v|-t type]\n", name);
}

void 
free_numq(struct numq* series)
{
	tailq_num *num_item;
	while ((num_item = TAILQ_FIRST(series))) {
		TAILQ_REMOVE(series, num_item, entries);
		free(num_item);
	}
}

int
main(int argc, char *argv[])
{
	char *type = (char *) NULL;
	int opt = 0;

	while ((opt = getopt(argc, argv, "vht:")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'v':
			printf("Version: \n");
			return 0;
		case 't':
			type = optarg;
			break;
		default:	/* '?' */
			usage(argv[0]);
			return 1;
		}
	}
	
	/*
	if (argc == 1) {
		usage(argv[0]);
		return 1;
	}
	*/

	tailq_num* number;
	struct numq* series = NULL;
	series = calloc(1, sizeof(struct numq));
	if (series == NULL) {
		perror("malloc failed");
		return 1;
	}
	TAILQ_INIT(series);

	char line[1024], *p, *e;
	long v;
	while (fgets(line, sizeof(line), stdin)) {
	    p = line;
	    for (p = line; ; p = e) {
		v = strtol(p, &e, 10);
		if (p == e)
		    break;
		number = calloc(1, sizeof(tailq_num));
		if (number == NULL) {
			perror("malloc failed");
			free_numq(series);
			return 1;
		}
		number->value = v;
		TAILQ_INSERT_TAIL(series, number, entries);
		printf("%ld\n", number->value);
	    }
	}
	free_numq(series);

	return 0;
}
