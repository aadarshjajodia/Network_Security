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
#include <map>
#include <vector>

using namespace std;
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
#define SIZE_DNS_ANSWER_DATA_1 16
#define SIZE_DNS_HEADER 12

map<u_short, vector<string> > ip_address_txid_map;
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

					char name1[100];
					char *domain = (char*)(packet + SIZE_ETHERNET + size_ip + 8 + SIZE_DNS_HEADER);
					char request[100];
					extract_dns_request(domain, request);
					int domain_length = strlen(domain);

					const struct dns_query *query1;
					query1 = (struct dns_query*)(packet + SIZE_ETHERNET + size_ip + 8 + SIZE_DNS_HEADER \
											 + domain_length + 1);
					if(ntohs(query1->type) != 1 ||  ntohs(query1->class1) != 1)
						return;

					const struct dns_answer_data_1 *query;
					query = (struct dns_answer_data_1*)(packet + SIZE_ETHERNET + size_ip + 8 + SIZE_DNS_HEADER \
											 + domain_length + 1 + 4);
					int j;
					char buffer[INET_ADDRSTRLEN];
					bool dns_spoofed = false;
				   	if(ip_address_txid_map[dns->id].size() > 0)
				    {
						fprintf(stderr, "DNS poisoning attempt\n");
						fprintf(stderr, "TXID %x Request %s\n", ntohs(dns->id), request);
						fprintf(stderr, "Answer1 ");
						for(int j=0;j<ip_address_txid_map[dns->id].size();j++)
						{
					    	    fprintf(stderr, "%s ", ip_address_txid_map[dns->id][j].c_str());
						}
						fprintf(stderr, "\nAnswer2 ");
				    	for(int i=0;i< ntohs(dns->ancount); i++)
				    	{
							const char *result = inet_ntop(AF_INET, &query->rdata, buffer, INET_ADDRSTRLEN);
							query = (struct dns_answer_data_1*)((char*)query + 16);
					    	fprintf(stderr, "%s ", buffer);
						}
						fprintf(stderr, "\n");
				    }
					else
					{
				    	for(int i=0;i< ntohs(dns->ancount); i++)
				    	{
							const char *result = inet_ntop(AF_INET, &query->rdata, buffer, INET_ADDRSTRLEN);
							query = (struct dns_answer_data_1*)((char*)query + 16);
					    	ip_address_txid_map[dns->id].push_back(string(buffer));
						}
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
		filter_expression_final = filter_expression_final + " and " + string(filter_exp);
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
