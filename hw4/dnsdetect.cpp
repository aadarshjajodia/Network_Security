#include <pcap.h>
#include <iostream>
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
#include <sys/ioctl.h>
#include <net/if.h>
#include <string>

using namespace std;
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
#define SIZE_DNS_ANSWER_DATA_1 16
#define SIZE_DNS_HEADER 12

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

struct dns_header {
	u_short id;
	u_short flags;
	u_short qdcount;
	u_short ancount;
	u_short nscount;
	u_short arcount;
};

struct dns_query {
	u_short type;
	u_short class1;
};

struct dns_answer_data{
    u_short type;
    u_short class1;
} __attribute__((packed, aligned(1)));

struct dns_answer_data_1{
    u_short name;
    u_short type;
    u_short class1;
    u_int ttl;    // 4 bytes for ttl
    u_short rdlength;    // 2 bytes for rdlength. This will be set to 4.
    u_int rdata; // 4 bytes for the IP address
} __attribute__((packed, aligned(1)));

struct dns_answer {
	u_char name[100];
	u_char separator;
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define TH_OFF(th)      		((th)->th_off)

char domain_name[100][100];
char ip_address[100][100];
static int m;
char attacker_ip[20];

u_short htons_1;
u_short htons_8180;
u_short htons_c00c;

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

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
void print_payload(const u_char *payload, int len)
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

void print_ip_packet(const u_char *packet, u_char **payload, int *size_payload)
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
			{
					const struct dns_header *dns;
					dns = (struct dns_header*)(packet + SIZE_ETHERNET + size_ip + 8);
					fprintf(stderr, "DNS ID is %d Answer count is %d\n", ntohs(dns->id), ntohs(dns->ancount));

					// Forging the DNS Answer

					// Copying the domain name
					char name1[100];
					//memset(name1, '\0', sizeof(name1));
					char *domain = (char*)(packet + SIZE_ETHERNET + size_ip + 8 + SIZE_DNS_HEADER);
					int domain_length = strlen(domain);

					const struct dns_answer_data_1 *query;
					query = (struct dns_answer_data_1*)(packet + SIZE_ETHERNET + size_ip + 8 + SIZE_DNS_HEADER \
											 + domain_length + 1 + 4);

					printf("Response Start\n");
					u_char *pay1 = (u_char*)query;
					print_payload(pay1, 16);
					printf("Response End\n");
			}
			break;
		default:
			break;
	}
}
void
got_packet(u_char *stringExpression, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* declare pointers to packet headers */
	const struct ether_header *ethernet;  /* The ethernet header [1] */

	int size_payload;
	u_char *payload;
	
	ethernet = (struct ether_header*)(packet);
	
	switch(ntohs(ethernet->ether_type))
	{
		case ETHERTYPE_IP:
			print_ip_packet(packet, &payload, &size_payload);
			break;
		default:
			break;
	}
}

int main(int argc, char **argv)
{
	//thiszone = localtime(0);
	char *dev = NULL;			/* capture device name */
	char *pcapFileName = NULL;
	char *stringExpression = NULL;
	char *filter_exp = NULL;		/* filter expression [3] */

	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 0, index;			/* number of packets to capture */

	char c;
	while ((c = getopt (argc, argv, "i:r:")) != -1)
	{
		switch(c) {
			case 'i':
					dev = optarg;
					break;
			case 'r':
					pcapFileName = optarg;
					break;
			default:
					break;
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
			return -1;
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

	string filter_expression_final = "udp and src port domain";
	if(filter_exp != NULL)
		filter_expression_final = filter_expression_final + string(filter_exp);
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		return -1;
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_expression_final.c_str(), 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		return -1;
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		return -1;
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, (u_char*)stringExpression);

	pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}
