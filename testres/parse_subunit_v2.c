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
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <zlib.h>

#include "parse_subunit_v2.h"

// https://github.com/testing-cabal/subunit/blob/master/python/subunit/v2.py#L412
// https://github.com/testing-cabal/subunit

uint32_t read_field(FILE *stream) {

    uint32_t field_value = 0;
    uint8_t byte = 0, byte0 = 0;
    uint16_t buf = 0;
    uint8_t prefix = 0;

    fread(&byte, 1, 1, stream);
    prefix = byte >> 6;
    byte0 = byte & 0x3f;
    if (prefix == 0x00) {
       field_value = byte0;
    } else if (prefix == 0x40) {
       fread(&byte, 1, 1, stream);
       field_value = (byte0 << 8) | byte;
    } else if (prefix == 0x80) {
       fread(&buf, 2, 1, stream);
       field_value = (byte << 16) | buf;
    } else {
       fread(&byte, 1, 2, stream);
       field_value = (byte0 << 24) | byte << 8;
       fread(&byte, 1, 1, stream);
       field_value = field_value | byte;
    };

    return field_value;
}

int read_stream(FILE *stream) {

    while (!feof(stream)) {
	read_packet(stream);
    }
}

int read_packet(FILE *stream) {

    subunit_header header;
    fread(&header, sizeof(subunit_header), 1, stream);

    uint16_t flags = htons(header.flags);
    printf("SIGNATURE: %02hhX\n", header.signature);
    printf("FLAGS: %02hX\n", flags);
    assert(header.signature == SIGNATURE);

    int8_t version;
    version = HI(flags) >> 4;
    printf("\tVERSION: %d\n", version);
    assert(version == VERSION);

    int8_t status;
    status = flags & 0x0007;
    printf("\tSTATUS: %02hX\n", status);
    assert(status <= 0x0007);

    uint32_t field_value;
    field_value = read_field(stream);
    printf("TOTAL LENGTH: %d\n", field_value);
    assert(field_value < PACKET_MAX_LENGTH);

    if (flags & FLAG_TIMESTAMP) {
        printf("FLAG_TIMESTAMP ");
        field_value = read_field(stream);
        printf("%08hX\n", field_value);
    };
    if (flags & FLAG_TEST_ID) {
        printf("FLAG_TEST_ID ");
        field_value = read_field(stream);
        printf("%08hX\n", field_value);
    };
    if (flags & FLAG_TAGS) {
        printf("FLAG_TAGS ");
        field_value = read_field(stream);
        printf("%08hX\n", field_value);
    };
    if (flags & FLAG_MIME_TYPE) {
        printf("FLAG_MIME_TYPE ");
        field_value = read_field(stream);
        printf("%08hX\n", field_value);
    };
    if (flags & FLAG_FILE_CONTENT) {
        printf("FLAG_FILE_CONTENT ");
        field_value = read_field(stream);
        printf("%08hX\n", field_value);
    };
    if (flags & FLAG_ROUTE_CODE) {
        printf("FLAG_ROUTE_CODE ");
        field_value = read_field(stream);
        printf("%08hX\n", field_value);
    };
    if (flags & FLAG_EOF) {
        printf("FLAG_EOF\n");
    };
    if (flags & FLAG_RUNNABLE) {
        printf("FLAG_RUNNABLE\n");
    };
    printf("CRC32: ");
    field_value = read_field(stream);
    printf("%08hX\n", field_value);

    return 0;
}


/*

CRC32
const char *s = "0xb30x2901b329010c03666f6f";
printf("%lX, should be %X\n", crc32(0, (const void*)s, strlen(s)), sample_crc32);

https://rosettacode.org/wiki/CRC-32#C
http://csbruce.com/software/crc32.c

Parse timestamp
int y, M, d, h, m;
float sec;
char *dateStr = "2014-11-12T19:12:14.505Z";
sscanf(dateStr, "%d-%d-%dT%d:%d:%fZ", &y, &M, &d, &h, &m, &sec);

UTF-8
https://github.com/benkasminbullock/unicode-c/blob/master/unicode.c
https://github.com/clibs/cutef8

*/
