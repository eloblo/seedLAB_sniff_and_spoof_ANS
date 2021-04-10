#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include "headers.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <errno.h>

#define IP4_HDRLEN 20
#define ICMP_HDRLEN 8 
#define DST "10.9.0.5"

unsigned short calculate_checksum(unsigned short * paddress, int len);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
   printf("Got a packet\n");
   //extract the ip header from the packet
   struct sniff_ip *ip = (struct sniff_ip*)(packet + sizeof(struct sniff_ethernet)); 
   //extract data
   char *data = (char*)(packet + sizeof(struct sniff_ip) + sizeof(struct sniff_ethernet) + sizeof(struct icmp_hdr));
   int len = (int)(header->len) - sizeof(struct sniff_ip) - sizeof(struct sniff_ethernet) - sizeof(struct icmp_hdr);
   
   struct ip iphdr; 
   struct icmp icmphdr; 

    //building ip header
    iphdr.ip_v = 4;
    iphdr.ip_hl = 5; 
    iphdr.ip_ttl = 128;
    iphdr.ip_p = IPPROTO_ICMP;
    if (inet_pton (AF_INET, inet_ntoa(ip->ip_dst), &(iphdr.ip_src)) <= 0) 
    {
        fprintf (stderr, "inet_pton() failed for source-ip with error: %d", errno);
        return;
    }
    if (inet_pton (AF_INET, DST, &(iphdr.ip_dst)) <= 0)
    {
        fprintf (stderr, "inet_pton() failed for destination-ip with error: %d" , errno);
        return;
    }

    //building icmp header
    //extract a pointer to icmp header
    struct icmp *picmp = (struct icmp*)(packet + sizeof(struct sniff_ip) + sizeof(struct sniff_ethernet)); 
    icmphdr = *picmp;   //copy copy the header
    icmphdr.icmp_type = 0;  //set to reply
    icmphdr.icmp_cksum = 0;

    //combining the headers to a reply packet
    char reply[IP_MAXPACKET];
    memcpy (reply, &iphdr, IP4_HDRLEN);
    memcpy ((reply + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);
    memcpy (reply + IP4_HDRLEN + ICMP_HDRLEN, data, len);
    //set checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (reply + IP4_HDRLEN), ICMP_HDRLEN + len);
    memcpy ((reply + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);
    
    //set destination for socket
    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = iphdr.ip_dst.s_addr;
    
    //opening socket
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) 
    {
        fprintf (stderr, "socket() failed with error: %d", errno);
        return;
    }
    //set socket options
    const int flagOne = 1;
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &flagOne, sizeof (flagOne)) == -1) 
    {
        fprintf (stderr, "setsockopt() failed with error: %d", errno);
        return;
    }
    //send reply
    if (sendto (sock, reply, IP4_HDRLEN + ICMP_HDRLEN + len, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1)  
    {
        fprintf (stderr, "sendto() failed with error: %d", errno);
        return;
    }

  close(sock);
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "proto ICMP and src 10.9.0.5";
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

// Compute checksum 
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}
