#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 

int32_t gmt2local(time_t t);

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define TH_OFF(th)      		((th)->th_off)

struct icmphdr
{
  u_short type;		/* message type */
  u_short code;		/* type sub-code */
  u_int checksum;
  u_long restofHeader;
};

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_ECHO		8	/* Echo Request			*/

int tflag = 1;
int32_t thiszone;
/* TCP header */

/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

void print_ip_packet(char *args, const u_char *packet, u_char **payload, int *size_payload, u_char* stringExpression)
{
	const struct sniff_ip *ip;              /* The IP header */

	int size_ip;
	int size_tcp;
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_UDP:
			sprintf(args + strlen(args)," UDP");
			int size_udp;
			const struct udphdr *udp;            /* The UDP header */
			udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);

			sprintf(args + strlen(args), " %s:%d ->", inet_ntoa(ip->ip_src), ntohs(udp->uh_sport));
			sprintf(args + strlen(args), " %s:%d ", inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));

			*payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8);
			*size_payload = ntohs(ip->ip_len) - (size_ip + 8);
			if (stringExpression == NULL || ((*size_payload > 0) && strstr((char*)*payload, (char*)stringExpression))){
				sprintf(args + strlen(args), " Payload (%d bytes):", *size_payload);
				printf("%s\n", args);
				print_payload(*payload, *size_payload);
			}
			break;
		default:
			break;
	}
}
void
got_packet(u_char *stringExpression, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct ether_header *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */

	int size_payload;
	u_char *payload;

	char args[1000];
	//sprintf(args, "\nPacket number %d:\n", count);
	count++;
	
	char buffer[26];
	struct tm* tm_info;
	tm_info = localtime(&header->ts.tv_sec);
	strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
	sprintf(args, "%s.%06u ", buffer, header->ts.tv_usec);

   	//ts_print(&(header->ts));

	/* define ethernet header */
	ethernet = (struct ether_header*)(packet);
	
	sprintf(args + strlen(args), "%02x:%02x:%02x:%02x:%02x:%02x", ethernet->ether_shost[0],
									ethernet->ether_shost[1],
									ethernet->ether_shost[2],
									ethernet->ether_shost[3],
									ethernet->ether_shost[4],
									ethernet->ether_shost[5]);

	sprintf(args + strlen(args), " -> ");

	sprintf(args + strlen(args), "%02x:%02x:%02x:%02x:%02x:%02x", ethernet->ether_dhost[0],
									ethernet->ether_dhost[1],
									ethernet->ether_dhost[2],
									ethernet->ether_dhost[3],
									ethernet->ether_dhost[4],
									ethernet->ether_dhost[5]);
	sprintf(args + strlen(args), " ethertype ");
	switch(ntohs(ethernet->ether_type))
	{
		case ETHERTYPE_IP:
			sprintf(args + strlen(args), "IPv4 ");
			sprintf(args + strlen(args), "(0x%x)", ntohs(ethernet->ether_type));
			sprintf(args + strlen(args), " length %u", header->len);
			print_ip_packet(args, packet, &payload, &size_payload, stringExpression);
			break;
		case ETHERTYPE_ARP:
			sprintf(args + strlen(args), "ARP ");
			sprintf(args + strlen(args), "(0x%x)", ntohs(ethernet->ether_type));
			sprintf(args + strlen(args), " length %u", header->len);
			const struct arphdr *arpheader = NULL;
			arpheader = (struct arphdr *)(packet+14); /* Point to the ARP header */ 
			printf("%s\n", args);
			break;
		default:
			sprintf(args + strlen(args)," OTHER");
			printf("%s\n", args);
			break;
	}
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
}

int main(int argc, char **argv)
{
	//thiszone = localtime(0);
	char *dev = NULL;			/* capture device name */
	char *pcapFileName = NULL;
	char *stringExpression = NULL;
	char *filter_exp;		/* filter expression [3] */

	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 0, index;			/* number of packets to capture */

	char c;
	while ((c = getopt (argc, argv, "i:r:s:")) != -1)
	{
		switch(c) {
			case 'i':
					dev = optarg;
					break;
			case 'r':
					pcapFileName = optarg;
					break;
			case 's':
					stringExpression = optarg;
					break;
			default:
					abort();
		}

    }
    index = optind;
    filter_exp = argv[index];

    if(dev == NULL)
    {
    	dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	if(pcapFileName != NULL)
	{
		handle = pcap_open_offline(pcapFileName, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open file %s: %s\n", pcapFileName, errbuf);
			exit(EXIT_FAILURE);
		}
	}
	else
	{
		handle = pcap_open_live(dev, SNAP_LEN, 0, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(EXIT_FAILURE);
		}
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, (u_char*)stringExpression);

	pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}