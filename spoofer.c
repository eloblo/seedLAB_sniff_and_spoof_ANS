#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>

#define IP4_HDRLEN 20
#define ICMP_HDRLEN 8 
#define SRC "8.8.8.8"
#define DST "10.9.0.5"

unsigned short calculate_checksum(unsigned short * paddress, int len);

int main ()
{
    struct ip iphdr; 
    struct icmp icmphdr; 
    char data[IP_MAXPACKET] = "This is the ping.\n";
    int datalen = strlen(data) + 1;

    //building ip header
    iphdr.ip_v = 4;
    iphdr.ip_hl = 5; 
    iphdr.ip_ttl = 128;
    iphdr.ip_p = IPPROTO_ICMP;
    if (inet_pton (AF_INET, SRC, &(iphdr.ip_src)) <= 0) 
    {
        fprintf (stderr, "inet_pton() failed for source-ip with error: %d", errno);
        return -1;
    }

    if (inet_pton (AF_INET, DST, &(iphdr.ip_dst)) <= 0)
    {
        fprintf (stderr, "inet_pton() failed for destination-ip with error: %d" , errno);
        return -1;
    }

    //building icmp header
    icmphdr.icmp_type = ICMP_ECHO;
    icmphdr.icmp_code = 0;
    icmphdr.icmp_id = 18; 
    icmphdr.icmp_seq = 0;
    icmphdr.icmp_cksum = 0;

    //combining the headers to a packet
    char packet[IP_MAXPACKET];
    memcpy (packet, &iphdr, IP4_HDRLEN);
    memcpy ((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);
    memcpy (packet + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet + IP4_HDRLEN), ICMP_HDRLEN + datalen);
    memcpy ((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = iphdr.ip_dst.s_addr;
    
    //opening socket
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) 
    {
        fprintf (stderr, "socket() failed with error: %d", errno);
        return -1;
    }

    const int flagOne = 1;
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &flagOne, sizeof (flagOne)) == -1) 
    {
        fprintf (stderr, "setsockopt() failed with error: %d", errno);
        return -1;
    }

    if (sendto (sock, packet, IP4_HDRLEN + ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1)  
    {
        fprintf (stderr, "sendto() failed with error: %d", errno);
        return -1;
    }

  close(sock);
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

