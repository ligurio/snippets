#include <stdint.h>

#ifndef PARSE_COMMON_H
#define PARSE_COMMON_H
#include "parse_common.h"
#endif /* PARSE_COMMON_H */

#define SUBUNIT_SIGNATURE 	0xB3
#define SUBUNIT_VERSION 	0x02
#define PACKET_MAX_LENGTH 	4194303

#define FLAG_TEST_ID		0x0800
#define FLAG_ROUTE_CODE		0x0400
#define FLAG_TIMESTAMP		0x0200
#define FLAG_RUNNABLE		0x0100
#define FLAG_TAGS		0x0080
#define FLAG_MIME_TYPE		0x0020
#define FLAG_EOF		0x0010
#define FLAG_FILE_CONTENT	0x0040

/*
struct packet {
    char     *test_id;
    char     *route_code;
    uint32_t timestamp;
    uint32_t status;
    char     *tags[];
};

typedef struct packet packet;
*/

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

uint32_t read_field(FILE *stream);
tailq_test *read_packet(FILE *stream);
struct suiteq *parse_subunit_v2(FILE *stream);
int is_subunit_v2(char* path);
