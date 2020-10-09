#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

#include "printers.h"

#define WRONG_ARGS_ERR (-1)
#define THREAD_ERR (-2)
#define SIGNAL_ERR (-3)

#define SNIFF_IP 0x01
#define SNIFF_TCP 0x02
#define SNIFF_UDP 0x04
#define SNIFF_ICMP 0x08
#define THREAD_RUNNING 0
#define THREAD_SET_STOP 1
#define THREAD_STOPPED 2

volatile int ip_stop = THREAD_RUNNING;
volatile int tcp_stop = THREAD_RUNNING;
volatile int udp_stop = THREAD_RUNNING;
volatile int icmp_stop = THREAD_RUNNING;

static FILE* rsniffer_log;

static int get_skt(int proto) {
  int skt = socket(AF_INET, SOCK_RAW, proto);
  if (skt < 0) {
    printf("Cant get socket\n");
    return -1;
  }
  return skt;
}

static ssize_t get_pkt(int skt, uint8_t* buf, size_t sz) {
  struct sockaddr_in saddr;
  socklen_t saddr_len = sizeof(saddr);
  ssize_t read_bytes = recvfrom(skt, buf, sz, 0, (struct sockaddr*)&saddr, &saddr_len);
  return read_bytes;
}

static void* sniff_ip(void* args) {
  // ??
}

static void* sniff_tcp(void* args) {
  uint8_t read_buf[65536];
  int skt = get_skt(IPPROTO_TCP);
  if (skt < 0)
    return 0;

  while (tcp_stop != THREAD_SET_STOP) {
    ssize_t sz = get_pkt(skt, read_buf, sizeof(read_buf));
    if (sz < 0) {
      perror("recvfrom");
      return 0;
    }
    struct iphdr ip = *(struct iphdr*)(read_buf);
    if (ip.protocol != 6)
      continue;
    print_tcp(read_buf, sz, rsniffer_log);
  }

  tcp_stop = THREAD_STOPPED;
  close(skt);
}

static void* sniff_udp(void* args) {
  uint8_t read_buf[65536];
  int skt = get_skt(IPPROTO_UDP);
  if (skt < 0)
    return 0;

  while (udp_stop != THREAD_SET_STOP) {
    ssize_t sz = get_pkt(skt, read_buf, sizeof(read_buf));
    if (sz < 0) {
      perror("recvfrom");
      return 0;
    }
    struct iphdr ip = *(struct iphdr*)(read_buf);
    if (ip.protocol != 17)
      continue;
    print_udp(read_buf, sz, rsniffer_log);
  }

  udp_stop = THREAD_STOPPED;
  close(skt);
}

static void* sniff_icmp(void* args) {
  uint8_t read_buf[65536];
  int skt = get_skt(IPPROTO_ICMP);
  if (skt < 0)
    return 0;

  while (icmp_stop != THREAD_SET_STOP) {
    ssize_t sz = get_pkt(skt, read_buf, sizeof(read_buf));
    if (sz < 0) {
      perror("recvfrom");
      return 0;
    }
    struct iphdr ip = *(struct iphdr*)(read_buf);
    if (ip.protocol != 1)
      continue;
    print_icmp(read_buf, sz, rsniffer_log);
  }

  icmp_stop = THREAD_STOPPED;
  close(skt);
}

static void run_sniffer(int flags) {
  pthread_t threads[4] = {0, 0, 0, 0};
  int i;
  if (flags & SNIFF_TCP) {
    if (pthread_create(&threads[1], NULL, sniff_tcp, NULL) != 0) {
      printf("Error: cannot start tcp thread\n");
      exit(THREAD_ERR);
    }
    if (pthread_detach(threads[1]) != 0) {
      printf("Error: cannot detach tcp thread\n");
      exit(THREAD_ERR);
    }
  }
  if (flags & SNIFF_UDP) {
    if (pthread_create(&threads[2], NULL, sniff_udp, NULL) != 0) {
      printf("Error: cannot start udp thread\n");
      exit(THREAD_ERR);
    }
    if (pthread_detach(threads[2]) != 0) {
      printf("Error: cannot detach udp thread\n");
      exit(THREAD_ERR);
    }
  }
  if (flags & SNIFF_ICMP) {
    if (pthread_create(&threads[2], NULL, sniff_icmp, NULL) != 0) {
      printf("Error: cannot start icmp thread\n");
      exit(THREAD_ERR);
    }
    if (pthread_detach(threads[2]) != 0) {
      printf("Error: cannot detach icmp thread\n");
      exit(THREAD_ERR);
    }
  }
}

static void print_help(const char* exec_name) {
  printf("USAGE: %s [-log FILENAME]\n", exec_name);
}

static FILE* open_log(const char* log_file) {
  FILE* log = fopen(log_file, "a");
  if (log == NULL) {
    printf("Error opening log file %s: %s\n", log_file, strerror(errno));
    return NULL;
  }
  return log;
}

int main(int argc, char** argv) {
  if (argc == 3) {
    if (strcmp(argv[1], "-log")) {
      print_help(argv[0]);
      exit(WRONG_ARGS_ERR);
    }
    rsniffer_log = open_log(argv[2]);
    if (rsniffer_log == NULL) {
      print_help(argv[0]);
      exit(WRONG_ARGS_ERR);
    }
  } else if (argc == 1) {
    rsniffer_log = stdout;
  } else {
    print_help(argv[0]);
    exit(WRONG_ARGS_ERR);
  }

  sigset_t waitset;
  sigemptyset(&waitset);
  sigaddset(&waitset, SIGINT);
  if (pthread_sigmask(SIG_BLOCK, &waitset, NULL) != 0) {
    printf("Error: cannot set sigmask: %s\n", strerror(errno));
    exit(SIGNAL_ERR);
  }
  printf("Sniffer is running... Press CRTL+C to stop.\n");
  run_sniffer(SNIFF_IP | SNIFF_TCP | SNIFF_UDP | SNIFF_ICMP);

  int sig = 0;
  while (sig != SIGINT) {
    sigwait(&waitset, &sig);
  }

  tcp_stop = THREAD_SET_STOP;
  udp_stop = THREAD_SET_STOP;
  icmp_stop = THREAD_SET_STOP;

  while (tcp_stop != THREAD_STOPPED &&
         udp_stop != THREAD_STOPPED &&
         icmp_stop != THREAD_STOPPED) {}
  printf("\nSniffer is stopped. Bye\n");
}