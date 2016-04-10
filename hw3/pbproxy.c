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

typedef struct {
	int socket;
	socklen_t address_length;
	const unsigned char *key;
	struct sockaddr_in red_addr;
	struct sockaddr address;
}thread_data;

void print_usage()
{
	printf("\nUSAGE: ./pbproxy "\
	       "[-l listening_port] [-k key_input_file] [destination] [destination_port]\n");
	printf("-l : proxy port for inbound connections\n");
	printf("-k: input key file\n");
	printf("destination : destination address to be relayed to\n");
	printf("destination_port : destination port to be relayed to\n\n");

}

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

unsigned char * encrypt_buffer(const unsigned char *buf, int n, const unsigned char *key)
{
	AES_KEY aes_key;
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char *result = NULL;
	ctr_state state;

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
	ctr_state state;

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

int read_from_pbproxy_write_to_server(int new_sock, thread_data *data)
{
	char buffer[PAGE_SIZE];
	int n;
	unsigned const char *result=NULL;
	memset(buffer, 0, sizeof(buffer));
	while ((n = read(data->socket, buffer, PAGE_SIZE)) >= 0) 
	{
		if (n == 0)
			return -1;
		result = decrypt_buffer((const unsigned char *)buffer, n, data->key);
		if (result == NULL)
			return -1;
		write(new_sock, result, n - AES_BLOCK_SIZE);
		free((void *)result);
		if (n < PAGE_SIZE)
			break;
	}
	return 0;
}
int read_from_server_write_to_pbproxy(int new_sock, thread_data *data)
{
	char buffer[PAGE_SIZE];
	int n;
	unsigned const char *result=NULL;
	memset(buffer, 0, sizeof(buffer));
	while ((n = read(new_sock, buffer, PAGE_SIZE)) > 0) 
	{
		if (n == 0)
			return -1;
		result = encrypt_buffer((const unsigned char *)buffer, n, data->key);
		if (result == NULL)
			return -1;
	    write(data->socket, result, n + AES_BLOCK_SIZE);                   
	    free((void *)result);
		if (n < PAGE_SIZE)
			break;
	}
	return 0;
}
void* process_request(void* arg) {

	thread_data *data= NULL;
	int new_sock;
	pthread_detach(pthread_self());

	if (arg == NULL) pthread_exit(NULL); 
	data = (thread_data *)arg;
	
	new_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(new_sock, (struct sockaddr *)&data->red_addr, sizeof(data->red_addr)) == -1)
	{
		printf("Connect failed!!!\n");
		pthread_exit(NULL);
	}

	int flags = fcntl(data->socket, F_GETFL);
	if (flags == -1)
		goto exit;
	fcntl(data->socket, F_SETFL, flags | O_NONBLOCK);
	flags = fcntl(new_sock, F_GETFL);
	if (flags == -1)
		goto exit;
	fcntl(new_sock, F_SETFL, flags | O_NONBLOCK);

	while (1) 
	{
		if(read_from_pbproxy_write_to_server(new_sock, data) == -1)
			goto exit;
		if(read_from_server_write_to_pbproxy(new_sock, data) == -1)
			goto exit;
	}

exit:
	printf("%s\n", "Exiting!");
	close(data->socket);
	close(new_sock);
	pthread_exit(NULL);
}

void client_read_stdin_write_to_socket(int sockfd, const unsigned char *key)
{
	unsigned char *result = NULL;
	int n;
	char buffer[PAGE_SIZE];
	while ((n = read(STDIN_FILENO, buffer, PAGE_SIZE)) >= 0) 
	{
		if (n == 0)
			exit(0);
		result = encrypt_buffer((const unsigned char *)buffer, n, key);
		if (result == NULL)
			exit(0);
		write(sockfd, result, n + AES_BLOCK_SIZE);
		free((void *) result);
		if (n < PAGE_SIZE)
			break;
	}
}
void client_read_socket_write_to_stdout(int sockfd, const unsigned char *key)
{
	unsigned char *result = NULL;
	int n;
	char buffer[PAGE_SIZE];
	while ((n = read(sockfd, buffer, PAGE_SIZE)) >= 0) 
	{
		if (n == 0)
			exit(0);

		result = decrypt_buffer((const unsigned char *)buffer, n, key);
		if (result == NULL)
			exit(0);
		write(STDOUT_FILENO, result, n - AES_BLOCK_SIZE);
		free((void *)result);
		if (n < PAGE_SIZE)
			break;
	}
}

int main(int argc, char *argv[]) {
	bool is_server_mode = false;
	char *key_file = NULL, *destination = NULL, *destination_port = NULL, *listening_port = NULL;;
	struct hostent *he;
	int lcount = 0, kcount = 0, opt, dst_port, error = 0;
	unsigned char *key = NULL;

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
	
	struct sockaddr_in serv_addr, red_addr;
	int sockfd;
	if (is_server_mode) 
	{
		pthread_t process_thread;
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
		}
		
		while (1)
		{
			thread_data *td;
			td = malloc(sizeof(thread_data));
			td->socket = accept(sockfd, &td->address, &td->address_length);
			if (td->socket < 0) 
			{
				printf("%s\n", "Accept failed!\n");
				return 0;
			}

			td->red_addr = red_addr;
			td->key = key;
			pthread_create(&process_thread, NULL, process_request, (void *) td);
		}
	}
	else 
	{

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
			client_read_stdin_write_to_socket(sockfd, key);
			client_read_socket_write_to_stdout(sockfd, key);
		}
	}
}