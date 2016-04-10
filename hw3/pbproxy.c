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
	struct sockaddr_in server_redirect_address;
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

unsigned char* generate_iv_for_aes(ctr_state *state)
{
	unsigned char *iv;
	iv = (unsigned char *)malloc(sizeof(unsigned char) * AES_BLOCK_SIZE);
	if(!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        printf("%s\n", "Failed to generate IV!!!");
        return NULL;
    }
    init_ctr(state, iv);
    return iv;
}
unsigned char * encrypt_buf(int n, const unsigned char *key, const unsigned char *buf)
{
	AES_KEY aes_key;
	unsigned char *iv;
	unsigned char *result = NULL;
	ctr_state state;

	iv = generate_iv_for_aes(&state);
	if(iv == NULL)
		return NULL;

    if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
        printf("%s\n", "AES set encryption key error");
        return NULL;
    }
    result = (unsigned char *) malloc(n + AES_BLOCK_SIZE);
    memcpy(result, iv, AES_BLOCK_SIZE);

    AES_ctr128_encrypt(buf, result + AES_BLOCK_SIZE, n, &aes_key,
    	state.ivec, state.ecount, &state.num);
    return result;    
}

unsigned char * decrypt_buf(int n, const unsigned char *key, const unsigned char *buf)
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
	unsigned char *source = NULL;
	FILE *fp = fopen(filename, "r");
	if (fp != NULL) 
	{
    	/* Go to the end of the file. */
    	if (fseek(fp, 0L, SEEK_END) == 0) 
    	{
	        /* Get the size of the file. */
	        long bufsize = ftell(fp);
	        if (bufsize == -1)
	        	return NULL;

	        /* Allocate our buffer to that size. */
	        source = malloc(sizeof(char) * (bufsize + 1));

	        /* Go back to the start of the file. */
	        if (fseek(fp, 0L, SEEK_SET) != 0)
	        	return NULL;

	        /* Read the entire file into memory. */
	        size_t newLen = fread(source, sizeof(char), bufsize, fp);
	        if (newLen == 0)
	        {
	        	free(source);
	        	return NULL;
	        }
	        source[newLen++] = '\0'; /* Just to be safe. */
	        fclose(fp);
	        return source;
    	}
    	return NULL;
    }
    return NULL;
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
		result = decrypt_buf(n, data->key, (const unsigned char *)buffer);
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
		result = encrypt_buf(n, data->key, (const unsigned char *)buffer);
		if (result == NULL)
			return -1;
	    write(data->socket, result, n + AES_BLOCK_SIZE);                   
	    free((void *)result);
		if (n < PAGE_SIZE)
			break;
	}
	return 0;
}
void* process_request(void* arg)
{
	if (arg == NULL) pthread_exit(NULL);
	thread_data *data = (thread_data *)arg;
	int new_sock;
	pthread_detach(pthread_self());

	int flags = fcntl(data->socket, F_GETFL);
	if (flags == -1)
		goto exit;
	fcntl(data->socket, F_SETFL, flags | O_NONBLOCK);
	
	new_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(new_sock, (struct sockaddr *)&data->server_redirect_address, sizeof(data->server_redirect_address)) == -1)
	{
		printf("Connect failed!!!\n");
		pthread_exit(NULL);
	}

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
		result = encrypt_buf(n, key, (const unsigned char *)buffer);
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

		result = decrypt_buf(n, key, (const unsigned char *)buffer);
		if (result == NULL)
			exit(0);
		write(STDOUT_FILENO, result, n - AES_BLOCK_SIZE);
		free((void *)result);
		if (n < PAGE_SIZE)
			break;
	}
}

int main(int argc, char *argv[]) {
	bool is_server_mode = 0;
	char *key_file = NULL, *destination = NULL, *destination_port = NULL, *listening_port = NULL;;
	int lcount = 0, kcount = 0, opt, dst_port, error = 0;
	unsigned char *key = NULL;
	struct hostent *he;

	while ((opt = getopt(argc, argv, "l:k:")) != -1)
	{
		switch(opt)
		{
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
					is_server_mode = 1;
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
	
	struct sockaddr_in server_address, server_redirect_address;
	int sockfd;
	if (is_server_mode) 
	{
		pthread_t process_thread;
		int portno;

		portno = atoi(listening_port);
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		bzero((char *) &server_address, sizeof(server_address));

   		server_address.sin_port = htons(portno);
   		server_address.sin_family = AF_INET;
   		server_address.sin_addr.s_addr = INADDR_ANY;
		
		server_redirect_address.sin_addr.s_addr = ((struct in_addr *)(he->h_addr_list[0]))->s_addr;
		server_redirect_address.sin_family = AF_INET;
		server_redirect_address.sin_port = htons(dst_port);
		
		if (bind(sockfd, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) 
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

			td->server_redirect_address = server_redirect_address;
			td->key = key;
			pthread_create(&process_thread, NULL, process_request, (void *) td);
		}
	}
	else 
	{

		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		server_address.sin_addr.s_addr = ((struct in_addr *)(he->h_addr_list[0]))->s_addr;
		server_address.sin_family = AF_INET;
		server_address.sin_port = htons(dst_port);
		
		if (connect(sockfd, (struct sockaddr *)&server_address, sizeof(server_address)) == -1) 
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