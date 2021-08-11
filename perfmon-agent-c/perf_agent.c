#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define TCP_PORT 3450
#define BACKLOG 10
#define BUFFER_SIZE 1024
#define VERSION "0.1.0"

#ifdef __cplusplus
#define CM_CAST(TYPE, EXPR) static_cast<TYPE>(EXPR)
#else
#define CM_CAST(TYPE, EXPR) (TYPE)(EXPR)
#endif

enum metric_id {
  CPU_COMBINED,
  CPU_IDLE,
  CPU_IRQ,
  CPU_NICE,
  CPU_SOFTIRQ,
  CPU_STOLEN,
  CPU_IOWAIT,
  CPU_PERCENT,
  CPU_TOTAL,
  CPU_SYSTEM,
  CPU_USER,
  MEM_VIRTUAL,
  MEM_SHARED,
  MEM_PAGEFAULTS,
  MEM_MAJORFAULTS,
  MEM_MINORFAULTS,
  MEM_RESIDENT,
  MEM_ACTUALFREE,
  MEM_ACTUALUSED,
  MEM_FREE,
  MEM_FREEPERC,
  MEM_RAM,
  MEM_TOTAL,
  MEM_USED,
  MEM_USEDPERC,
  SWAP_PAGEIN,
  SWAP_PAGEOUT,
  SWAP_FREE,
  SWAP_TOTAL,
  SWAP_USED,
  DISKS_AVAILABLE,
  DISKS_QUEUE,
  DISKS_READBYTES,
  DISKS_READS,
  DISKS_SERVICE,
  DISKS_WRITEBYTES,
  DISKS_WRITES,
  DISKS_FILES,
  DISKS_FREE,
  DISKS_FREEFILES,
  DISKS_TOTAL,
  DISKS_USEPERC,
  DISKS_USED,
  NET_BYTESRECV,
  NET_RXDROPS,
  NET_RXERR,
  NET_RXFRAME,
  NET_RXOVERRUNS,
  NET_RX,
  NET_BYTESSENT,
  NET_TXCARRIER,
  NET_TXCOLLISIONS,
  NET_TXDROPS,
  NET_TXERR,
  NET_TXOVERRUNS,
  NET_USED,
  NET_SPEED,
  NET_TX,
  TCP_BOUND,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_CLOSING,
  TCP_ESTAB,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_IDLE,
  TCP_INBOUND,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_OUTBOUND,
  TCP_SYN_RECV,
  TCP_TIME_WAIT
};

enum class_id {
  CPU,
  MEMORY,
  DISKS,
  SWAP,
  NETWORK,
  TCP
};

static void *fn_test(void) {
  fprintf(stderr, "Yep!\n");
  return NULL;
}

static void *fn_exit(void) {
  exit(0);
}

static void *fn_shutdown(void) {
  fprintf(stderr, "%s\n", __func__);
  return NULL;
}

static void *fn_exec(void) {
  fprintf(stderr, "%s\n", __func__);
  return NULL;
}

static void *fn_tail(void) {
  fprintf(stderr, "%s\n", __func__);
  return NULL;
}

static char *fn_metric(void) {
  fprintf(stderr, "%s\n", __func__);

  // memory: virtual,shared,pagefaults,majorfaults,minorfaults,resident
  // memory: actualfree,actualused,free,freeperc,ram,total,used,usedperc
  // disks: available,queue,readbytes,reads,service,writebytes,
  // disks: writes,files,free,freefiles,total,useperc,used
  // swap: pagein,pageout,free,total,used
  // network: bytesrecv,rxdrops,rxerr,rxframe,rxoverruns,rx,
  // network: bytessent,txcarrier,txcollisions,txdrops,txerr,txoverruns,
  // network: used,speed,tx
  // tcp: bound,close,close_wait,closing,estab,fin_wait1,fin_wait2
  // tcp: idle,inbound,last_ack,listen,outbound,syn_recv,time_wait

  enum metric_id metric = CPU_COMBINED;
  switch (metric) {
  case CPU_COMBINED:
    printf("1\n");
  case CPU_IDLE:
    printf("2\n");
  case CPU_IRQ:
    printf("2\n");
  case CPU_SOFTIRQ:
    printf("2\n");
  case CPU_STOLEN:
    printf("2\n");
  case CPU_IOWAIT:
    printf("2\n");
  case CPU_PERCENT:
    printf("2\n");
  case CPU_TOTAL:
    printf("2\n");
  case CPU_SYSTEM:
    printf("2\n");
  case CPU_USER:
    printf("2\n");
  }

  return NULL;
}

typedef struct {
  const char* name;
  enum metric_id metric;
  enum class_id class;
} metricMapEntry;

static metricMapEntry id_map_metric[] = {{"combined", CPU_COMBINED, CPU},
  {"idle", CPU_IDLE, CPU},
  {"irq", CPU_IRQ, CPU},
  {"nice", CPU_NICE, CPU},
  {"softirq", CPU_SOFTIRQ, CPU},
  {"stolen", CPU_STOLEN, CPU},
  {"iowait", CPU_IOWAIT, CPU},
  {"percent", CPU_PERCENT, CPU},
  {"total", CPU_TOTAL, CPU},
  {"system", CPU_SYSTEM, CPU},
  {"user", CPU_USER, CPU},
  {"virtual", MEM_VIRTUAL, MEMORY},
  {"shared", MEM_SHARED, MEMORY},
  {"pagefaults", MEM_PAGEFAULTS, MEMORY},
  {"majorfaults", MEM_MAJORFAULTS, MEMORY},
  {"minorfaults", MEM_MINORFAULTS, MEMORY},
  {"resident", MEM_RESIDENT, MEMORY},
  {"actualfree", MEM_ACTUALFREE, MEMORY},
  {"actualused", MEM_ACTUALUSED, MEMORY},
  {"free", MEM_FREE, MEMORY},
  {"freeperc", MEM_FREEPERC, MEMORY},
  {"ram", MEM_RAM, MEMORY},
  {"total", MEM_TOTAL, MEMORY},
  {"used", MEM_USED, MEMORY},
  {"usedperc", MEM_USEDPERC, MEMORY},
  {"pagein", SWAP_PAGEIN, SWAP},
  {"pageout", SWAP_PAGEOUT, SWAP},
  {"free", SWAP_FREE, SWAP},
  {"total", SWAP_TOTAL, SWAP},
  {"used", SWAP_USED, SWAP},
  {"available", DISKS_AVAILABLE, DISKS},
  {"queue", DISKS_QUEUE, DISKS},
  {"readbytes", DISKS_READBYTES, DISKS},
  {"reads", DISKS_READS, DISKS},
  {"service", DISKS_SERVICE, DISKS},
  {"writebytes", DISKS_WRITEBYTES, DISKS},
  {"writes", DISKS_WRITES, DISKS},
  {"files", DISKS_FILES, DISKS},
  {"free", DISKS_FREE, DISKS},
  {"freefiles", DISKS_FREEFILES, DISKS},
  {"total", DISKS_TOTAL, DISKS},
  {"useperc", DISKS_USEPERC, DISKS},
  {"used", DISKS_USED, DISKS},
  {"bytesrecv", NET_BYTESRECV, NETWORK},
  {"rxdrops", NET_RXDROPS, NETWORK},
  {"rxerr", NET_RXERR, NETWORK},
  {"rxframe", NET_RXFRAME, NETWORK},
  {"rxoverruns", NET_RXOVERRUNS, NETWORK},
  {"rx", NET_RX, NETWORK},
  {"bytessent", NET_BYTESSENT, NETWORK},
  {"txcarrier", NET_TXCARRIER, NETWORK},
  {"txcollisisions", NET_TXCOLLISIONS, NETWORK},
  {"txdrops", NET_TXDROPS, NETWORK},
  {"txerr", NET_TXERR, NETWORK},
  {"txoverruns", NET_TXOVERRUNS, NETWORK},
  {"used", NET_USED, NETWORK},
  {"speed", NET_SPEED, NETWORK},
  {"tx", NET_TX, NETWORK},
  {"bound", TCP_BOUND, TCP},
  {"close", TCP_CLOSE, TCP},
  {"close_wait", TCP_CLOSE_WAIT, TCP},
  {"closing", TCP_CLOSING, TCP},
  {"estab", TCP_ESTAB, TCP},
  {"fin_wait1", TCP_FIN_WAIT1, TCP},
  {"fin_wait2", TCP_FIN_WAIT2, TCP},
  {"idle", TCP_IDLE, TCP},
  {"inbound", TCP_INBOUND, TCP},
  {"last_ack", TCP_LAST_ACK, TCP},
  {"listen", TCP_LISTEN, TCP},
  {"outbound", TCP_OUTBOUND, TCP},
  {"syn_recv", TCP_SYN_RECV, TCP},
  {"time_wait", TCP_TIME_WAIT, TCP},
                                           {NULL, 0, 0}};

typedef void (*FuncPointer)(void);

typedef struct {
  const char *name;
  FuncPointer func;
} functionMapEntry;

static functionMapEntry fn_map_command[] = {{"test", fn_test},
                                           {"exit", fn_exit},
                                           {"shutdown", fn_shutdown},
                                           {"interval", NULL},
                                           {"exec", fn_exec},
                                           {"tail", fn_tail},
                                           {"metrics", fn_metric},
                                           {"metrics-single", fn_metric}};

static const int num_commands =
    CM_CAST(int, sizeof(fn_map_command) / sizeof(functionMapEntry)) - 1;

static const int num_metrics =
    CM_CAST(int, sizeof(id_map_metric) / sizeof(metricMapEntry)) - 1;

typedef struct {
  enum class_id class;
  enum metric_id metric;
  bool is_once;
  const char *obj;
  int interval;
} parameters;

FuncPointer parse_request(const char *buf, parameters *p) {
  char *b = strdup(buf);
  char *c = NULL;
  bool is_found = false;
  FuncPointer fn = NULL;

  c = strsep(&b, ":");
  for (int i = 0; i < num_commands; ++i) {
    if (strcmp(c, fn_map_command[i].name) == 0) {
      printf("FOUND %s\n", fn_map_command[i].name);
      fn = fn_map_command[i].func;
      is_found = true;
    }
  }
  if (!is_found) {
      goto teardown;
  }

  if ((strcmp(c, "tail") == 0) || (strcmp(c, "exec") == 0)) {
    p->obj = b;
  }

  if (strcmp(c, "metrics-single") == 0) {
    p->is_once = true;
  } else if (strcmp(c, "metrics") == 0) {
    p->is_once = false;
  }

  c = strsep(&b, ":");
  is_found = false;
  for (int i = 0; i < num_metrics; ++i) {
    if ((strcmp(c, id_map_metric[i].name) == 0) &&
		(p->class == id_map_metric[i].class)) {
      printf("FOUND %s\n", id_map_metric[i].name);
      p->metric = id_map_metric[i].metric;
      is_found = true;
    }
  }
  if (!is_found) {
      goto teardown;
  }

teardown:
  free(b);
  free(c);

  return fn;
};

static void usage(char *path) {
  char *name = basename(path);
  fprintf(stderr, "Usage: %s [-v] [-m] [-l]\n", name);
}

int main(int argc, char *argv[]) {
  int current_interval = 0, opt = 0;
  bool print_metrics = false;
  bool listen_mode = false;

  while ((opt = getopt(argc, argv, "vml")) != -1) {
    switch (opt) {
    case 'v':
      printf("%s\n", VERSION);
      return 0;
    case 'm':
      print_metrics = true;
      break;
    case 'l':
      listen_mode = true;
      break;
    default:
      usage(argv[0]);
      return EXIT_FAILURE;
    }
  }

  if (print_metrics) {
    printf("Supported commands:");
    for (int i = 0; i < num_commands; ++i) {
      printf(" '%s'", fn_map_command[i].name);
    }
    printf("\n");

    return EXIT_SUCCESS;
  }

  if (argc == 1 || !listen_mode) {
    usage(argv[0]);
    return EXIT_FAILURE;
  }

  int sockfd, fd;
  struct sockaddr_in local_addr;
  struct sockaddr_in remote_addr;
  int sin_size;

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    return EXIT_FAILURE;
  }

  int option = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
  local_addr.sin_family = AF_INET;
  local_addr.sin_port = htons(TCP_PORT);
  local_addr.sin_addr.s_addr = INADDR_ANY;
  bzero(&(local_addr.sin_zero), 8);

  int rc =
      bind(sockfd, (struct sockaddr *)&local_addr, sizeof(struct sockaddr));
  if (rc == -1) {
    perror("bind");
    return EXIT_FAILURE;
  }

  fprintf(stderr, "Listen on TCP port %d\n", TCP_PORT);
  if (listen(sockfd, BACKLOG) == -1) {
    perror("listen");
    return EXIT_FAILURE;
  }

  printf("Waiting for incoming connection...\n");
  sin_size = sizeof(struct sockaddr_in);
  if ((fd = accept(sockfd, (struct sockaddr *)&remote_addr, &sin_size)) == -1) {
    perror("accept");
    return EXIT_FAILURE;
  }
  printf("Connection accepted %s\n", inet_ntoa(remote_addr.sin_addr));

  char buf[BUFFER_SIZE];
  while (1) {
    int rc = recv(fd, buf, BUFFER_SIZE, 0);
    if (rc == -1) {
      close(fd);
      return EXIT_FAILURE;
    }
    buf[rc] = 0;
    send(fd, buf, rc, 0);
    buf[rc - 1] = 0;
    parameters p = { };
    p.interval = current_interval;
    FuncPointer fn = parse_request(buf, &p);
    if (p.interval != 0) {
        current_interval = p.interval;
    } else {
        p.interval = current_interval;
    }
    if ((!fn) && (p.interval != 0)) {
      fprintf(stderr, "Unknown command or metric\n");
      continue;
    }
    (*fn)();
  }
  close(fd);

  return EXIT_SUCCESS;
}
