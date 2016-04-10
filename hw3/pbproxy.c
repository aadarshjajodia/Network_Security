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

struct send_data {
	int new_sock;
	const unsigned char *key;
	struct sockaddr_in red_addr;
};

void print_usage()
{
	printf("\nUSAGE: ./pbproxy "\
	       "[-l listening_port] [-k key_input_file] [destination] [destination_port]\n");
	printf("-l : proxy port for inbound connections\n");
	printf("-k: input key file\n");
	printf("destination : destination address to be relayed to\n");
	printf("destination_port : destination port to be relayed to\n\n");

}
/* Strcutures taken from http://stackoverflow.com/questions/29441005/aes-ctr-encryption-and-decryption */
struct ctr_state 
{ 
    unsigned char ivec[AES_BLOCK_SIZE];  
    unsigned int num; 
    unsigned char ecount[AES_BLOCK_SIZE]; 
}; 

void init_ctr(struct ctr_state *state, const unsigned char iv[16])
{        
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
     * first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}

unsigned char * encrypt_buffer(const unsigned char *buf, int n, const unsigned char *key)
{
	AES_KEY aes_key;
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char *result = NULL;
	struct ctr_state state;

    if(!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        printf("%s\n", "Error in random bytes generation!!!");
        return NULL;    
    }
    if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
        printf("%s\n", "AES set encryption key error");
        return NULL;
    }
    result = (unsigned char *) malloc(n + AES_BLOCK_SIZE);
    memcpy(result, iv, AES_BLOCK_SIZE);
    init_ctr(&state, iv);
    AES_ctr128_encrypt(buf, result + AES_BLOCK_SIZE, n, &aes_key,
    	state.ivec, state.ecount, &state.num);
    return result;    
}

unsigned char * decrypt_buffer(const unsigned char *buf, int n, const unsigned char *key)
{
	AES_KEY aes_key;
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char *result = NULL;
	struct ctr_state state;

    if ((AES_set_encrypt_key(key, 128, &aes_key)) < 0) {
        printf("%s\n", "AES set encryption key error");
        return NULL;
    }
    memcpy(iv, buf, AES_BLOCK_SIZE);
    init_ctr(&state, iv);
    result = (unsigned char *) malloc(n - AES_BLOCK_SIZE);
    AES_ctr128_encrypt(buf + AES_BLOCK_SIZE, result, n - AES_BLOCK_SIZE,
    	&aes_key, state.ivec, state.ecount, &state.num);
    return result;
}

unsigned char* readFile(const char* filename)
{
	unsigned char *buffer = NULL;
	long length;
	FILE *fp = fopen(filename, "r");
	if (fp)
	{
		// Using fseek to calculate the length of the file. 
		fseek(fp, 0, SEEK_END);
		length = ftell(fp);

		// Using fseek to to move the file pointer to the beginning of the file. 
		fseek(fp, 0, SEEK_SET);
		buffer = malloc(length);
		if (buffer)
			fread(buffer, 1, length, fp);
		fclose (fp);
	}
	return buffer;
}

void* process_request(void* arg) {

	struct send_data *data= NULL;
	char buffer[PAGE_SIZE];
	int new_sock, n;
	unsigned const char *result=NULL;

	pthread_detach(pthread_self());
	printf("%s\n", "A new thread is spawned");

	if (arg == NULL) pthread_exit(NULL); 
	data = (struct send_data *)arg;
	
	new_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(new_sock, (struct sockaddr *)&data->red_addr, sizeof(data->red_addr)) == -1) {
		printf("Connect failed!!!\n");
		pthread_exit(NULL);
	}
	int flags = fcntl(data->new_sock, F_GETFL);
	if (flags == -1)
		goto exit;
	fcntl(data->new_sock, F_SETFL, flags | O_NONBLOCK);
	flags = fcntl(new_sock, F_GETFL);
	if (flags == -1)
		goto exit;
	fcntl(new_sock, F_SETFL, flags | O_NONBLOCK);

	memset(buffer, 0, sizeof(buffer));
	while (1) {
		while ((n = read(data->new_sock, buffer, PAGE_SIZE)) >= 0) {
			if (n == 0) goto exit;
			result = decrypt_buffer((const unsigned char *)buffer, n, data->key);
			if (result == NULL)
				goto exit;
			write(new_sock, result, n - AES_BLOCK_SIZE);
			free((void *)result);
			if (n < PAGE_SIZE)
				break;
		}
		while ((n = read(new_sock, buffer, PAGE_SIZE)) > 0) {
			if (n == 0) goto exit;
			result = encrypt_buffer((const unsigned char *)buffer, n, data->key);
			if (result == NULL)
				goto exit;    
            write(data->new_sock, result, n + AES_BLOCK_SIZE);                   
            free((void *)result);
			if (n < PAGE_SIZE)
				break;
		}
	}

exit:
	printf("%s\n", "Exiting!");
	close(data->new_sock);
	close(new_sock);
	pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
	int opt, dst_port, error = 0;
	char *listening_port = NULL;
	bool is_server_mode = false;
	char *key_file = NULL;
	char *destination = NULL;
	char *destination_port = NULL;
	unsigned char *key = NULL;
	struct hostent *he;
	int lcount = 0, kcount = 0;

	while ((opt = getopt(argc, argv, "l:k:")) != -1) {
		switch(opt) {
			case 'l':
				if (lcount > 0) 
				{
					printf("-l option can be used only once\n");
					error = 1;
				}
				else
				{
					lcount++;
					listening_port = optarg;
					is_server_mode = true;
				}
				break;
			case 'k':
				if (kcount > 0) 
				{
					printf("-k option can be used only once\n");
					error = 1;
				}
				else
				{
					kcount++;
					key_file = optarg;
				}
				break;
			case '?':
				error = 1;
				break;
			default:
				error = 1;
		}
	}
	
	if (key_file == NULL || error)
	{
		print_usage();	
		return 0;
	}

	if (optind < argc - 2) 
	{
		print_usage();	
		return 0;
	}
	else
	{
		destination = argv[optind];
		destination_port = argv[optind+1];
	}
	
	key = readFile(key_file);
	if (!key) {
		printf("Reading file failed!!!\n");
		return 0;
	}
	
	dst_port = atoi(destination_port);
	if ((he=gethostbyname(destination)) == 0) {
		printf("%s\n", "gethostbyname rror!\n");
		return 0;
	}
	
	if (is_server_mode == true) {
		struct sockaddr_in serv_addr, red_addr;
		pthread_t process_thread;
		int sockfd;
		int portno;

		portno = atoi(listening_port);
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		bzero((char *) &serv_addr, sizeof(serv_addr));

		serv_addr.sin_family = AF_INET;
   		serv_addr.sin_addr.s_addr = INADDR_ANY;
   		serv_addr.sin_port = htons(portno);
		
		red_addr.sin_family = AF_INET;
		red_addr.sin_port = htons(dst_port);
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
		
		while (1) {
			struct sockaddr_in cli_addr;
			socklen_t clilen;
			int newsockfd;
			struct send_data* sd;

			clilen = sizeof(cli_addr);		
			newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
			if (newsockfd < 0) 
     		{
     			printf("%s\n", "Accept failed!\n");
				return 0;
     		}
     		sd = (struct send_data *)malloc(sizeof(struct send_data));
			sd->red_addr = red_addr;
			sd->key = key;
			sd->new_sock = newsockfd;
			pthread_create(&process_thread, NULL, process_request, (void *) sd);
		}
		
	}
	else 
	{
		struct sockaddr_in serv_addr;
		int sockfd, n;
		char buffer[PAGE_SIZE];
		unsigned const char *result=NULL;

		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(dst_port);
		serv_addr.sin_addr.s_addr = ((struct in_addr *)(he->h_addr_list[0]))->s_addr;
		
		if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) 
		{
			printf("%s\n", "Connect failed");
			return 0;
		}
		
		fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
		fcntl(sockfd, F_SETFL, O_NONBLOCK);
		
		while(1) 
		{
			while ((n = read(STDIN_FILENO, buffer, PAGE_SIZE)) >= 0) 
			{
				if (n == 0)
					return 0;
				result = encrypt_buffer((const unsigned char *)buffer, n, key);
				if (result == NULL)
					return 0;
				write(sockfd, result, n + AES_BLOCK_SIZE);
				free((void *) result);
				if (n < PAGE_SIZE)
					break;
			}
			while ((n = read(sockfd, buffer, PAGE_SIZE)) >= 0) 
			{
				if (n == 0)
					return 0;

				result = decrypt_buffer((const unsigned char *)buffer, n, key);
				if (result == NULL)
					return 0;
				write(STDOUT_FILENO, result, n - AES_BLOCK_SIZE);
				free((void *)result);
				if (n < PAGE_SIZE)
					break;
			}
		}
	}
}