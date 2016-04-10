#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>

#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>

#define PAGE_SIZE 4096


typedef struct 
{
	int socket;
	socklen_t address_length;
	const unsigned char *key;
	struct sockaddr_in red_addr;
	struct sockaddr address;
}thread_data;

typedef struct 
{ 
    unsigned char ivec[AES_BLOCK_SIZE];  
    unsigned int num; 
    unsigned char ecount[AES_BLOCK_SIZE]; 
}ctr_state; 

void init_ctr(ctr_state *state, const unsigned char iv[16])
{        
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    memset(state->ivec + 8, 0, 8);
    memcpy(state->ivec, iv, 8);
}
unsigned char * encrypt_buf(const unsigned char *buf, int n, const unsigned char *key)
{
	AES_KEY aes_key;
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char *result = NULL;
	ctr_state state;

    if(!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        printf("%s\n", "Unable to generate Random Bytes Needed for Initialization Vector");
        return NULL;    
    }
    if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
        printf("%s\n", "Unable to set key needed for AES encryption");
        return NULL;
    }
    result = (unsigned char *) malloc(n + AES_BLOCK_SIZE);
    memcpy(result, iv, AES_BLOCK_SIZE);
    init_ctr(&state, iv);
    AES_ctr128_encrypt(buf, result + AES_BLOCK_SIZE, n, &aes_key,
    	state.ivec, state.ecount, &state.num);
    return result;    
}

unsigned char * decrypt_buf(const unsigned char *buf, int n, const unsigned char *key)
{
	AES_KEY aes_key;
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char *result = NULL;
	ctr_state state;

    if ((AES_set_encrypt_key(key, 128, &aes_key)) < 0) {
        printf("%s\n", "Unable to set key needed for AES decryption");
        return NULL;
    }
    memcpy(iv, buf, AES_BLOCK_SIZE);
    init_ctr(&state, iv);
    result = (unsigned char *) malloc(n - AES_BLOCK_SIZE);
    AES_ctr128_encrypt(buf + AES_BLOCK_SIZE, result, n - AES_BLOCK_SIZE,
    	&aes_key, state.ivec, state.ecount, &state.num);
    return result;
}
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
	else
	{
		// pbproxy - client mode
		struct sockaddr_in serv_addr;
		int sockfd, n;
		char buffer[PAGE_SIZE];
		unsigned const char *result=NULL;
		sockfd = socket(AF_INET, SOCK_STREAM, 0);

		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(dest_port);
		serv_addr.sin_addr.s_addr = ((struct in_addr *)(he->h_addr_list[0]))->s_addr;

		if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
			printf("%s\n", "Connect failed");
			return 0;
		}
		fprintf(stderr, "Connected to server\n");
		fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
		fcntl(sockfd, F_SETFL, O_NONBLOCK);
	}
}