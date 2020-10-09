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
#define SOCKET_ERR (-4)

#define SNIFF_IP 0x01
#define SNIFF_TCP 0x02
#define SNIFF_UDP 0x04
#define SNIFF_ICMP 0x08
#define THREAD_RUNNING 0
#define THREAD_SET_STOP 1
#define THREAD_STOPPED 2
#define PKT_BUF_SIZE 65536

volatile int ip_stop = THREAD_RUNNING;
volatile int tcp_stop = THREAD_RUNNING;
volatile int udp_stop = THREAD_RUNNING;
volatile int icmp_stop = THREAD_RUNNING;

static FILE* rsniffer_log = NULL;
static pthread_mutex_t rsniffer_log_mtx = PTHREAD_MUTEX_INITIALIZER;

volatile static int ZERO = 0;

static void crash(int reason) {
  ZERO = reason / ZERO;
}

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
  ssize_t read_bytes;
  while (1) {
    read_bytes = recvfrom(skt, buf, sz, MSG_DONTWAIT, (struct sockaddr*)&saddr, &saddr_len);
    if (read_bytes < 0 && errno == EAGAIN)
      continue;
    break;
  }
  return read_bytes;
}

static void* sniff_tcp(void* args) {
  int skt = get_skt(IPPROTO_TCP);
  if (skt < 0)
    crash(SOCKET_ERR);
  uint8_t buf[PKT_BUF_SIZE];
  struct sockaddr_in saddr;
  socklen_t saddr_len = sizeof(saddr);
  ssize_t read_bytes;

  while (tcp_stop != THREAD_SET_STOP) {
    read_bytes = recvfrom(skt, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&saddr, &saddr_len);
    if (read_bytes < 0) {
      if (errno == EAGAIN)
        continue;
      perror("recvfrom");
      break;
    }
    struct iphdr ip = *(struct iphdr*)(buf);
    if (ip.protocol != 6)
      continue;
    pthread_mutex_lock(&rsniffer_log_mtx);
    print_tcp(buf, read_bytes , rsniffer_log);
    pthread_mutex_unlock(&rsniffer_log_mtx);
  }

  tcp_stop = THREAD_STOPPED;
  close(skt);
}

static void* sniff_udp(void* args) {
  int skt = get_skt(IPPROTO_UDP);
  if (skt < 0)
    crash(SOCKET_ERR);
  uint8_t buf[PKT_BUF_SIZE];
  struct sockaddr_in saddr;
  socklen_t saddr_len = sizeof(saddr);
  ssize_t read_bytes;

  while (udp_stop != THREAD_SET_STOP) {
    read_bytes = recvfrom(skt, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&saddr, &saddr_len);
    if (read_bytes < 0) {
      if (errno == EAGAIN)
        continue;
      perror("recvfrom");
      break;
    }
    struct iphdr ip = *(struct iphdr*)(buf);
    if (ip.protocol != 17)
      continue;
    pthread_mutex_lock(&rsniffer_log_mtx);
    print_udp(buf, read_bytes, rsniffer_log);
    pthread_mutex_unlock(&rsniffer_log_mtx);
  }

  udp_stop = THREAD_STOPPED;
  close(skt);
}

static void* sniff_icmp(void* args) {
  int skt = get_skt(IPPROTO_ICMP);
  if (skt < 0)
    crash(SOCKET_ERR);
  uint8_t buf[PKT_BUF_SIZE];
  struct sockaddr_in saddr;
  socklen_t saddr_len = sizeof(saddr);
  ssize_t read_bytes;

  while (icmp_stop != THREAD_SET_STOP) {
    read_bytes = recvfrom(skt, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&saddr, &saddr_len);
    if (read_bytes < 0) {
      if (errno == EAGAIN)
        continue;
      perror("recvfrom");
      break;
    }
    struct iphdr ip = *(struct iphdr*)(buf);
    if (ip.protocol != 1)
      continue;
    pthread_mutex_lock(&rsniffer_log_mtx);
    print_icmp(buf, read_bytes, rsniffer_log);
    pthread_mutex_unlock(&rsniffer_log_mtx);
  }

  icmp_stop = THREAD_STOPPED;
  close(skt);
}

static void run_sniffer(int flags) {
  pthread_t threads[4];
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
  run_sniffer(SNIFF_TCP | SNIFF_UDP | SNIFF_ICMP);
  printf("Sniffer is running... Press CRTL+C to stop.\n");

  int sig = 0;
  while (sig != SIGINT)
    sigwait(&waitset, &sig);

  tcp_stop = THREAD_SET_STOP;
  udp_stop = THREAD_SET_STOP;
  icmp_stop = THREAD_SET_STOP;

  printf("\nStopping threads...\n");
  while (tcp_stop != THREAD_STOPPED &&
         udp_stop != THREAD_STOPPED &&
         icmp_stop != THREAD_STOPPED) {}
  printf("\nAll threads are stopped. Bye\n");
}