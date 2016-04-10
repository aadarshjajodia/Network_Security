#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>

void print_usage()
{
	printf("Usage is");
	printf("\n");
	return;
}
int fsize(FILE *fp){
	if(!fp) return -1;
    int prev=ftell(fp);
    fseek(fp, 0L, SEEK_END);
    int sz=ftell(fp);
    fseek(fp,prev,SEEK_SET); //go back to where we were
    return sz;
}

typedef struct {
	int socket;
	socklen_t address_length;
	const unsigned char *key;
	struct sockaddr_in red_addr;
	struct sockaddr address;
}thread_data;

void* process_request(void* arg) {
	return NULL;
}
unsigned char* readfile(const char *filename)
{
	if(filename == NULL)
		return NULL;
	FILE *fp = fopen(filename, "r");
	if(!fp)
	{
		printf("Unable to read file");
		return NULL;
	}
	else
	{
		int file_size = fsize(fp);
		if(file_size == -1)
		{
			printf("File is corrupt");
			return NULL;	
		}
		else
		{
			unsigned char* buffer = NULL;
			buffer = malloc(file_size);
			if (buffer)
			{
				fread(buffer, 1, file_size, fp);
				buffer[file_size-1] = '\0';
			}
			fclose (fp);
			return buffer;
		}
	}
}
int main(int argc, char *argv[])
{
	int opt, lcount = 0, kcount = 0, dest_port;
	int is_server_mode = 0;
	char *listening_port = NULL;
	char *keyfile = NULL;
	char *destination;
	char *destination_port;
	unsigned char* key = NULL;
	struct hostent *he;
	while ((opt = getopt(argc, argv, "l:k:")) != -1)
	{
		switch(opt)
		{
			case 'l':
				if(lcount > 0)
				{
					// This is an error here
					printf("-l option can be used only once\n");
					print_usage();
					return 0;
				}
				lcount++;
				is_server_mode = 1;
				listening_port = optarg;
				break;
			case 'k':
				if(kcount > 0)
				{
					// this is an error here
					printf("-k option can be used only once\n");
					print_usage();
					return 0;
				}
				kcount++;
				keyfile = optarg;
				break;
			default:
				printf("Unknown option\n");
				print_usage();
				return 0;
		}
	}
	if(keyfile == NULL)
	{
		printf("Key file can't be empty");
		print_usage();
		return 0;
	}
	if (optind == argc - 2) 
	{
		destination = argv[optind];
		destination_port = argv[optind+1];
	}
	else
	{
		print_usage();
		return 0;
	}
	dest_port = atoi(destination_port);
	if ((he=gethostbyname(destination)) == 0) {
		printf("%s\n", "gethostbyname error!\n");
		return 0;
	}
	//printf("Here");
	key = readfile(keyfile);
	//printf("Key Is: %s", key);
	//printf("Listeninf port is %s, destination is %s, destination_port is %s is_server_mode %d\n", listening_port, destination, destination_port, is_server_mode);
	if(is_server_mode)
	{
		//printf("Here asd\n");
		fprintf(stderr, "perror output string here\n");
		// The code for server
		thread_data *td;
		struct sockaddr_in serv_addr, red_addr;
		pthread_t process_thread;
		int sockfd;
		int portno;

		portno = atoi(listening_port);
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		//printf("Socket FD %d\n", sockfd);
		fprintf(stderr, "Here i am\n");
		fprintf(stderr, "Socket FD %d\n", sockfd);
		bzero((char *) &serv_addr, sizeof(serv_addr));
		
		
		serv_addr.sin_family = AF_INET;
   		serv_addr.sin_addr.s_addr = INADDR_ANY;
   		serv_addr.sin_port = htons(portno);
		
		red_addr.sin_family = AF_INET;
		red_addr.sin_port = htons(dest_port);
		red_addr.sin_addr.s_addr = ((struct in_addr *)(he->h_addr_list[0]))->s_addr;
		

		if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
        {
        	printf("%s\n", "ERROR in Binding");
        	return 0;
    	}

		if (listen(sockfd, 10) < 0) {
			printf("%s\n", "Listen failed!\n");
			return 0;
		};

		while (1)
		{
			fprintf(stderr, "While\n");
			td = malloc(sizeof(thread_data));
			td->socket = accept(sockfd, &td->address, &td->address_length);
			if (td->socket < 0) 
     		{
     			printf("%s\n", "Accept failed!\n");
				return 0;
     		}
     		fprintf(stderr, "Client Connected\n");
			td->red_addr = red_addr;
			td->key = key;
			pthread_create(&process_thread, NULL, process_request, (void *) td);
		}
	}
}