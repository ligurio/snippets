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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#define HI(x)  ((x) >> 8)
#define LO(x)  ((x) & 0xFF)

//  PACKET := SIGNATURE FLAGS PACKET_LENGTH
//            TIMESTAMP? TESTID? TAGS? MIME?
//            FILECONTENT? ROUTING_CODE? CRC32

typedef struct {
    uint8_t  signature;
    uint16_t flags;
    uint8_t  length;
} subunit_header;

// Timestamp when present is a 32 bit unsigned integer for seconds, and a variable
// length number for nanoseconds, representing UTC time since Unix Epoch in
// seconds and nanoseconds.
typedef uint32_t timestamp;

// Test id when present is a UTF-8 string. The test id should uniquely identify
// runnable tests such that they can be selected individually. For tests and other
// actions which cannot be individually run (such as test
// fixtures/layers/subtests) uniqueness is not required (though being human
// meaningful is highly recommended).

// Tags when present is a length prefixed vector of UTF-8 strings, one per tag.
// There are no restrictions on tag content (other than the restrictions on UTF-8
// strings in subunit in general). Tags have no ordering.

// When a MIME type is present, it defines the MIME type for the file across all
// packets same file (routing code + testid + name uniquely identifies a file,
// reset when EOF is flagged). If a file never has a MIME type set, it should be
// treated as application/octet-stream.

// File content when present is a UTF-8 string for the name followed by the length
// in bytes of the content, and then the content octets.

// If present routing code is a UTF-8 string. The routing code is used to
// determine which test backend a test was running on when doing data analysis,
// and to route stdin to the test process if interaction is required.

/*
Flags:

	High byte 		Low byte
	15 14 13 12 11 10 9 8 	7 6 5 4 3 2 1 0
	VERSION 		feature bits
*/

/*
Length:

	After the flags field is a number field giving the length in bytes for the
	entire packet including the signature and the checksum. This length must be
	less than 4MiB - 4194303 bytes.
*/

/*
VERSION must be  0x2 - version 2

If the version is not 0x2 then the packet cannot be read.  It is recommended to
signal an error at this point (e.g. by emitting a synthetic error packet and
returning to the top level loop to look for new packets, or exiting with an
error). If recovery is desired, treat the packet signature as an opaque byte
and scan for a new synchronisation point.
*/

// Feature bits:
//
//    Bit 11 	mask 0x0800 	Test id present.
//    Bit 10 	mask 0x0400 	Routing code present.
//    Bit 9 	mask 0x0200 	Timestamp present.
//    Bit 8 	mask 0x0100 	Test is 'runnable'.
//    Bit 7 	mask 0x0080 	Tags are present.
//    Bit 6 	mask 0x0040 	File content is present.
//    Bit 5 	mask 0x0020 	File MIME type is present.
//    Bit 4 	mask 0x0010 	EOF marker.
//    Bit 3 	mask 0x0008 	Must be zero in version 2.
//
// FIXME: typedef enum {value1, value2, value3, (...) } VALUE;
enum Feature { TestID,
	       RoutingCode,
	       Timestamp,
               Tags,
	       FileContent,
	       MIMEType,
	       EOFMarker };

// Test status gets three bits: Bit 2 | Bit 1 | Bit 0 - mask 0x0007.
// A test status enum lookup:
//
//    000 - undefined / no test
//    001 - Enumeration / existence
//    002 - In progress
//    003 - Success
//    004 - Unexpected Success
//    005 - Skipped
//    006 - Failed
//    007 - Expected failure
//
enum TestStatus { Undefined,
		  Enumeration,
		  InProgress,
                  Success,
                  UnexpectedSuccess,
		  Skipped,
		  Failed,
		  ExpectedFailure };

int is_set(uint8_t feature_bits, int flag) {

    char bits[8];
    bits[0] = feature_bits;
    bits[1] = feature_bits >> 8;
    bits[2] = feature_bits >> 7;
    bits[3] = feature_bits >> 6;
    bits[4] = feature_bits >> 5;
    bits[5] = feature_bits >> 4;
    bits[6] = feature_bits >> 3;
    bits[7] = feature_bits >> 2;

    if (bits[flag]) {
       return 0;
    }

    return 1;
}

int main()
{  
    
    // Packet sample, with test id, runnable set, status=enumeration.
    // Spaces below are to visually break up
    // signature / flags / length / testid / crc32:
    // b3 2901 0c 03666f6f 08555f1b

    subunit_header packet = { .signature = 0xb3, .flags = 0x2901, .length = 0x0c };
    unsigned sample_testid = 0x03666f6f;
    unsigned sample_crc32 = 0x08555f1b;

    printf("Signature: %02X\n", packet.signature);
    printf("Flags: %02X\n", packet.flags);
    printf("Length: %02X\n", packet.length);

    printf("TestId: %02X\n", sample_testid);
    printf("CRC32: %02X\n", sample_crc32);

    uint8_t version, feature_bits;

    version = HI(packet.flags);
    feature_bits = LO(packet.flags);
    printf("High byte (version): %02X\n", version);
    printf("Low byte (feature bits): %02X\n", feature_bits);

    char bits[8];
    bits[0] = feature_bits;
    bits[1] = feature_bits >> 8;
    bits[2] = feature_bits >> 7;
    bits[3] = feature_bits >> 6;
    bits[4] = feature_bits >> 5;
    bits[5] = feature_bits >> 4;
    bits[6] = feature_bits >> 3;
    bits[7] = feature_bits >> 2;

    int i;
    for (i = 0; i < 8; i += 1)  {
        printf("%02X\n", bits[i]);
    }

    if (bits[TestID]) {
       printf("TestID is present\n");
    }

    // ===========================================

    FILE *file;
    subunit_header header;
    
    file = fopen("subunit-sample-01.subunit", "r");
    if (file == NULL)
    {
    	fprintf(stderr, "Error opening file\n");
    	return 1;
    }
    
    while (!feof(file)) {
        fread(&header, sizeof(subunit_header), 1, file);
        printf ("signature = %02X flags = %02X  length = %02X\n", header.signature, header.flags, header.length);
	/*
        version = HI(header.flags);
        feature_bits = LO(header.flags);
        printf("feature bits %d\n", feature_bits);
        printf("version %d\n", version);
        if (is_set(feature_bits, TestID) == 0)
           printf("TestID\n");
           fread(&header, sizeof(subunit_header), 1, file);
        if (is_set(feature_bits, RoutingCode) == 0)
           printf("RoutingCode\n");
        if (is_set(feature_bits, Timestamp) == 0)
           printf("Timestamp\n");
        if (is_set(feature_bits, Tags) == 0)
           printf("Tags\n");
        if (is_set(feature_bits, FileContent) == 0)
           printf("FileContent\n");
	*/
	char *content = malloc(header.length);
        fread(content, header.length, 1, file);
	free(content);
    }

    return 0;
}
