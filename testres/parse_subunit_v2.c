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

#define HI(x)  ((x) >> 8)
#define LO(x)  ((x) & 0xFF)

#define SIGNATURE 		0xB3
#define VERSION 		0x02
#define PACKET_MAX_LENGTH 	4194303

#define FLAG_TEST_ID		0x0800
#define FLAG_ROUTE_CODE		0x0400
#define FLAG_TIMESTAMP		0x0200
#define FLAG_RUNNABLE		0x0100
#define FLAG_TAGS		0x0080
#define FLAG_MIME_TYPE		0x0020
#define FLAG_EOF		0x0010
#define FLAG_FILE_CONTENT	0x0040

struct packet {
    char     *test_id;
    char     *route_code;
    char     *tags[];
    uint32_t timestamp;
    uint32_t status;
}

typedef packet packet;

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

uint32_t read_field(FILE *stream) {

    int32_t field = 0;
    int8_t byte = 0;
    int8_t n_octets = 0;
    uint8_t prefix = 0;

    fread(&byte, sizeof(byte), 1, stream);
    printf("FIRST BYTE %02hX ", byte);
    prefix = byte >> 6;
    printf("PREFIX %d\n", prefix);
    switch (prefix) {
        case 0x00:
            n_octets = 1;
            break;
        case 0x40:
            n_octets = 2;
            break;
        case 0x80:
            n_octets = 3;
            break;
        case 0xc0:
            n_octets = 4;
            break;
    }
    printf("Number of octets %d\n", n_octets);

    fseek(stream, -sizeof(byte), SEEK_CUR);
    fread(&field, n_octets, 1, stream);
    printf("Field value: %d\n", field);

    return field;
}
 
int read_packet(FILE *stream) {

    subunit_header header;
    fread(&header, sizeof(subunit_header), 1, stream);

    uint16_t flags = htons(header.flags);
    printf("Signature: %02hhX\n", header.signature);
    printf("Flags: %02hX\n", flags);
    assert(header.signature == SIGNATURE);

    int8_t version;
    version = HI(flags) >> 4;
    printf("Version %d\n", version);
    assert(version == VERSION);

    int8_t status;
    status = flags & 0x0007;
    printf("Status: %02hX\n", status);
    assert(status <= 0x0007);

    if (flags & FLAG_TIMESTAMP)
        printf("FLAG_TIMESTAMP ");
  	// read field
    if (flags & FLAG_TEST_ID)
        printf("FLAG_TEST_ID ");
  	// read field
    if (flags & FLAG_TAGS)
        printf("FLAG_TAGS ");
  	// read field
    if (flags & FLAG_MIME_TYPE)
        printf("FLAG_MIME_TYPE ");
  	// read field
    if (flags & FLAG_FILE_CONTENT)
        printf("FLAG_FILE_CONTENT ");
  	// read field
    if (flags & FLAG_ROUTE_CODE)
        printf("FLAG_ROUTE_CODE ");
  	// read field
    if (flags & FLAG_EOF)
        printf("FLAG_EOF ");
  	// read field
    if (flags & FLAG_RUNNABLE)
        printf("FLAG_RUNNABLE ");
  	// read field
    printf("\n");

    uint32_t field;
    field = read_field(stream);
    printf("Packet length: %d\n", htonl(field));
    assert(field < PACKET_MAX_LENGTH);

    char *content = malloc(field - 6);
    fread(content, field - 6, 1, stream);
    free(content);
}

int main()
{
    // Packet sample, with test id, runnable set, status=enumeration.
    // Spaces below are to visually break up:
    // signature / flags / length / testid / crc32
    // b3 2901 0c 03666f6f 08555f1b
    // echo 03666f6f | xxd -p -r

    subunit_header sample_header = { .signature = 0xb3, .flags = ntohs(0x2901) };
    uint32_t sample_length = ntohl(0x0c);
    uint32_t sample_testid = ntohl(0x03666f6f);
    uint32_t sample_crc32 = ntohl(0x08555f1b);

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
    name = "subunit-sample-01.subunit";
    
    printf("\nreading file %s\n", name);
    file = fopen(name, "r");
    if (file == NULL)
    {
    	fprintf(stderr, "Error opening file\n");
    	return 1;
    }
    
    /*
    subunit_header header;
    while (!feof(file)) {
	printf("===> next packet please\n");
	read_packet(file);
    }
    fclose(file);
    */

    /*

    // crc32
    const char *s = "0xb30x2901b329010c03666f6f";
    printf("%lX, should be %X\n", crc32(0, (const void*)s, strlen(s)), sample_crc32);

    https://rosettacode.org/wiki/CRC-32#C
    http://csbruce.com/software/crc32.c

    */

    /*
    // parse timestamp
    int y, M, d, h, m;
    float sec;
    char *dateStr = "2014-11-12T19:12:14.505Z";
    sscanf(dateStr, "%d-%d-%dT%d:%d:%fZ", &y, &M, &d, &h, &m, &sec);
    */

    return 0;
}
