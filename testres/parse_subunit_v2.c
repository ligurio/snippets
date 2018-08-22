/*
 * Copyright © 2018 Sergey Bronnikov <sergeyb@bronevichok.ru>
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
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>

#define HI(x)  ((x) >> 8)
#define LO(x)  ((x) & 0xFF)

#define SIGNATURE 		0xB3
#define VERSION 		0x02
#define LENGTH_THRESHOLD 	4194303
#define FLAG_TEST_ID		0x0800
#define FLAG_ROUTE_CODE		0x0400
#define FLAG_TIMESTAMP		0x0200
#define FLAG_RUNNABLE		0x0100
#define FLAG_TAGS		0x0080
#define FLAG_MIME_TYPE		0x0020
#define FLAG_EOF		0x0010
#define FLAG_FILE_CONTENT	0x0040

// https://github.com/testing-cabal/subunit/blob/master/python/subunit/v2.py#L405

struct subunit_header {
    uint8_t  signature;
    uint16_t flags;
} __attribute__ ((packed));

typedef struct subunit_header subunit_header;

typedef uint32_t timestamp;

enum TestStatus { Undefined,
		  Enumeration,
		  InProgress,
                  Success,
                  UnexpectedSuccess,
		  Skipped,
		  Failed,
		  ExpectedFailure };
 
int read_packet(FILE *stream) {

    subunit_header header;
    fread(&header, sizeof(subunit_header), 1, stream);

    printf("Signature: %02X\n", header.signature);
    printf("Flags: %02X\n", header.flags);
    assert(header.signature == SIGNATURE);

    uint8_t version;
    version = HI(header.flags) >> 4;
    printf("Version %d\n", version);
    //assert(version == VERSION);

    if (header.flags & FLAG_TEST_ID)
        printf("FLAG_TEST_ID ");
    if (header.flags & FLAG_ROUTE_CODE)
        printf("FLAG_ROUTE_CODE ");
    if (header.flags & FLAG_TIMESTAMP)
        printf("FLAG_TIMESTAMP ");
    if (header.flags & FLAG_RUNNABLE)
        printf("FLAG_RUNNABLE ");
    if (header.flags & FLAG_TAGS)
        printf("FLAG_TAGS ");
    if (header.flags & FLAG_MIME_TYPE)
        printf("FLAG_MIME_TYPE ");
    if (header.flags & FLAG_EOF)
        printf("FLAG_EOF ");
    if (header.flags & FLAG_FILE_CONTENT)
        printf("FLAG_FILE_CONTENT ");
    printf("\nStatus: %02X\n", header.flags & 0x0007);

    uint32_t length = 0;
    fread(&length, 3, 1, stream);
    printf("Length %x\n", length);
    //assert(length < LENGTH_THRESHOLD);

    char *content = malloc(length - 3);
    fread(content, length - 3, 1, stream);
    free(content);
}

int main()
{
    // Packet sample, with test id, runnable set, status=enumeration.
    // Spaces below are to visually break up:
    // signature / flags / length / testid / crc32
    // b3 2901 0c 03666f6f 08555f1b

    subunit_header sample_header = { .signature = 0xb3, .flags = 0x2901 };
    uint32_t sample_length = 0x0c;
    uint32_t sample_testid = 0x03666f6f;
    uint32_t sample_crc32 = 0x08555f1b;

    printf("header %zu\n", sizeof(subunit_header));

    char* buf = NULL;
    size_t buf_size= 0;
    FILE* stream = open_memstream(&buf, &buf_size);
    fwrite(&sample_header, 1, sizeof(sample_header), stream);
    fwrite(&sample_length, 1, sizeof(sample_length), stream);
    fwrite(&sample_testid, 1, sizeof(sample_testid), stream);
    fwrite(&sample_crc32, 1, sizeof(sample_crc32), stream);
    read_packet(stream);
    fclose(stream);
    free(buf);

    // ===========================================

    FILE *file;
    char *name;
    name = "01.subunit";
    
    printf("\nreading file %s\n", name);
    file = fopen(name, "r");
    if (file == NULL)
    {
    	fprintf(stderr, "Error opening file\n");
    	return 1;
    }
    
    subunit_header header;
    while (!feof(file)) {
	read_packet(file);
    }
    fclose(file);

    /*

    const char *s = "The quick brown fox jumps over the lazy dog";
    printf("%lX\n", crc32(0, (const void*)s, strlen(s)));

    https://rosettacode.org/wiki/CRC-32#C
    http://csbruce.com/software/crc32.c

    */

    return 0;
}
