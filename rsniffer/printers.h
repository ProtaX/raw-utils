#ifndef PRINTERS_H_
#define PRINTERS_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

/**
 * Taken from https://www.binarytides.com/packet-sniffer-code-c-linux/
 * Modified by ProtaX
 */
inline void print_data(uint8_t* data, size_t sz, FILE* log) {
  int i, j;
	for (i = 0; i < sz; i++)	{
		if (i != 0 && i % 16 == 0) {
			fprintf(log, "         ");
			for (j = i - 16; j < i; j++) {
				if (data[j] >= 32 && data[j] <= 128)
					fprintf(log, "%c", (unsigned char)data[j]);
				else
          fprintf(log, ".");
			}
			fprintf(log, "\n");
		}

		if (i % 16 == 0)
      fprintf(log, "   ");
		fprintf(log, " %02X", (unsigned int)data[i]);

		if (i == sz - 1) {
			for (j = 0; j < 15 - i % 16; j++)
        fprintf(log, "   ");
			
			fprintf(log, "         ");
			
			for (j = i - i % 16; j <= i; j++)	{
				if(data[j] >= 32 && data[j] <= 128)
          fprintf(log, "%c", (unsigned char)data[j]);
				else
          fprintf(log, ".");
			}
			fprintf(log, "\n");
		}
	}
}

inline void print_ip_hdr(uint8_t* buf, size_t sz, FILE* log) {
	unsigned short iphdrlen;
	struct sockaddr_in source;
  struct sockaddr_in dest;

	struct iphdr *iph = (struct iphdr *)buf;
	iphdrlen = iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	fprintf(log,"\n");
	fprintf(log,"IP Header\n");
	fprintf(log,"   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(log,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(log,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(log,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(log,"   |-Identification    : %d\n",ntohs(iph->id));
	//fprintf(log,"   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	//fprintf(log,"   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	//fprintf(log,"   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	fprintf(log,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(log,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(log,"   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(log,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
	fprintf(log,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

inline void print_tcp(uint8_t* buf, size_t sz, FILE* log) {
  unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)buf;
	iphdrlen = iph->ihl*4;

	struct tcphdr *tcph=(struct tcphdr*)(buf + iphdrlen);

	fprintf(log,"\n\n***********************TCP Packet*************************\n");	
	print_ip_hdr(buf, sz, log);
	fprintf(log,"\n");
	fprintf(log,"TCP Header\n");
	fprintf(log,"   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(log,"   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(log,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(log,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(log,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	//fprintf(log,"   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//fprintf(log,"   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	fprintf(log,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(log,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(log,"   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(log,"   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(log,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(log,"   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(log,"   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(log,"   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(log,"   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(log,"\n");
	fprintf(log,"                        DATA Dump                         ");
	fprintf(log,"\n");
		
	fprintf(log, "IP Header\n");
	print_data(buf, iphdrlen, log);
		
	fprintf(log, "TCP Header\n");
	print_data(buf + iphdrlen, tcph->doff*4, log);
		
	fprintf(log, "Data Payload\n");	
	print_data(buf + iphdrlen + tcph->doff*4 , (sz - tcph->doff*4-iph->ihl*4), log);
						
	fprintf(log,"\n###########################################################");
}

inline void print_icmp(uint8_t* buf, size_t sz, FILE* log) {
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)buf;
	iphdrlen = iph->ihl*4;

	struct icmphdr *icmph = (struct icmphdr *)(buf + iphdrlen);

	fprintf(log,"\n\n***********************ICMP Packet*************************\n");	

	print_ip_hdr(buf, sz, log);

	fprintf(log, "\n");

	fprintf(log, "ICMP Header\n");
	fprintf(log, "   |-Type : %d",(unsigned int)(icmph->type));

	if((unsigned int)(icmph->type) == 11) 
		fprintf(log, "  (TTL Expired)\n");
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) 
		fprintf(log, "  (ICMP Echo Reply)\n");
	fprintf(log, "   |-Code : %d\n", (unsigned int)(icmph->code));
	fprintf(log, "   |-Checksum : %d\n", ntohs(icmph->checksum));
	//fprintf(log, "   |-ID       : %d\n",ntohs(icmph->id));
	//fprintf(log, "   |-Sequence : %d\n",ntohs(icmph->sequence));
	fprintf(log, "\n");

	fprintf(log, "IP Header\n");
	print_data(buf, iphdrlen, log);

	fprintf(log, "UDP Header\n");
	print_data(buf + iphdrlen, sizeof(icmph), log);

	fprintf(log, "Data Payload\n");	
	print_data(buf + iphdrlen + sizeof(icmph), (sz - sizeof icmph - iph->ihl * 4), log);

	fprintf(log, "\n###########################################################");
}

void print_udp(uint8_t* buf, size_t sz, FILE* log) {
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)buf;
	iphdrlen = iph->ihl*4;

	struct udphdr *udph = (struct udphdr*)(buf + iphdrlen);

	fprintf(log, "\n\n***********************UDP Packet*************************\n");

	print_ip_hdr(buf, sz, log);

	fprintf(log, "\nUDP Header\n");
	fprintf(log, "   |-Source Port      : %d\n", ntohs(udph->source));
	fprintf(log, "   |-Destination Port : %d\n", ntohs(udph->dest));
	fprintf(log, "   |-UDP Length       : %d\n", ntohs(udph->len));
	fprintf(log, "   |-UDP Checksum     : %d\n", ntohs(udph->check));

	fprintf(log, "\n");
	fprintf(log, "IP Header\n");
	print_data(buf, iphdrlen, log);

	fprintf(log, "UDP Header\n");
	print_data(buf + iphdrlen, sizeof(udph), log);

	fprintf(log, "Data Payload\n");	
	print_data(buf + iphdrlen + sizeof(udph), (sz - sizeof(udph) - iph->ihl * 4), log);

	fprintf(log,"\n###########################################################");
}

#endif  // PRINTERS_H_