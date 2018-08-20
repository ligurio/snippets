#include <stdio.h>
#include <string.h>
#include <expat.h>
#include <fcntl.h>

#ifdef XML_LARGE_SIZE
# if defined(XML_USE_MSC_EXTENSIONS) && _MSC_VER < 1400
#  define XML_FMT_INT_MOD "I64"
# else
#  define XML_FMT_INT_MOD "ll"
# endif
#else
# define XML_FMT_INT_MOD "l"
#endif

#ifdef XML_UNICODE_WCHAR_T
# define XML_FMT_STR "ls"
#else
# define XML_FMT_STR "s"
#endif

#define BUFFSIZE        8192

char Buff[BUFFSIZE];

int Depth;

typedef struct {
	char* name;
	char* status;
	char* time;
} testcase;

typedef struct testsuite {
    char* name;
    char* hostname;
    char* timestamp;
    double time;
    int failures;
    int errors;
} testsuite_t;

typedef struct suite {
    testsuite_t *next;
    testsuite_t suite;
} suite_t;

static void XMLCALL
start(void *data, const XML_Char *elem, const XML_Char **attr)
{
  int i;
  (void)data;

  testsuite_t suite;
  if (strcmp(elem, "testsuite") == 0) {
     //printf("testsuite: %\n", XML_FMT_STR, elem);
     for (i = 0; attr[i]; i += 2) {
        //printf(" %" XML_FMT_STR "='%" XML_FMT_STR "'", attr[i], attr[i + 1]);
        //char attr_name = attr[i];
        //char attr_value = attr[i + 1];
        if (strcmp(attr[i], "name") == 0) {
           printf("name %s\n", attr[i + 1]);
        }
        if (strcmp(attr[i], "hostname") == 0) {
           printf("hostname %s\n", attr[i + 1]);
        }
        if (strcmp(attr[i], "timestamp") == 0) {
           printf("timestamp %s\n", attr[i + 1]);
        }
        if (strcmp(attr[i], "tests") == 0) {
           printf("tests %s\n", attr[i + 1]);
        }
        if (strcmp(attr[i], "failures") == 0) {
           printf("failures %s\n", attr[i + 1]);
        }
        if (strcmp(attr[i], "time") == 0) {
           printf("time %s\n", attr[i + 1]);
        }
        if (strcmp(attr[i], "errors") == 0) {
           printf("errors %s\n", attr[i + 1]);
        }
     }
  }
  Depth++;
}

static void XMLCALL
end(void *data, const XML_Char *el)
{
  (void)data;
  (void)el;

  Depth--;
}

void parse_junit(FILE *f) {
  XML_Parser p = XML_ParserCreate(NULL);
  if (! p) {
    fprintf(stderr, "Couldn't allocate memory for parser\n");
    exit(-1);
  }
  XML_SetElementHandler(p, start, end);

  printf("parse_junit()\n");
  for (;;) {
    int len, done;
    len = fread(Buff, 1, BUFFSIZE, f);
    if (ferror(f)) {
       fprintf(stderr, "Read error\n");
       exit(-1);
    }
    done = feof(f);

    if (XML_Parse(p, Buff, len, done) == XML_STATUS_ERROR) {
      fprintf(stderr,
              "Parse error at line %" XML_FMT_INT_MOD "u:\n%" XML_FMT_STR "\n",
              XML_GetCurrentLineNumber(p),
              XML_ErrorString(XML_GetErrorCode(p)));
      exit(-1);
    }

    if (done) {
       break;
    }
  }
  XML_ParserFree(p);
}
