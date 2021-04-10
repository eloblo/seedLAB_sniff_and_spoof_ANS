#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include "headers.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet)
{
   printf("Got a packet\n");
   //extract the ip header from the packet
   struct sniff_ip *ip = (struct sniff_ip*)(packet + sizeof(struct sniff_ethernet)); 
   //extract the tcp header
   //struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + sizeof(struct sniff_ip) + sizeof(struct sniff_ethernet));
   //extract data
   char *data = (char*)packet;
   int len = (int)(header->len); //extract the frame's size
   //print result
   printf("source ip %s\n", inet_ntoa(ip->ip_src));
   printf("destination ip %s\n", inet_ntoa(ip->ip_dst));
   printf("protocol %d\n",ip->ip_p);
   printf("data: %c\n",*(data + len - 1));
   
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "proto TCP and dst port 23 ";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("br-0338c03034a9", BUFSIZ, 0, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);              
  pcap_setfilter(handle, &fp);                                

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                    

  pcap_close(handle);   //Close the handle
  return 0;
}
