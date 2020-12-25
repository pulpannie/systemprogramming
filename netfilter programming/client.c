#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pthread.h>

/** define constants and global variables
 * author: jiseong
 * date: 2020.11.10
 */
#define MAX_CONN 10
#define MAX_CONN_ON_PORT 5
#define BUF_SIZE 512
#define LOG_HEADER_LEN 24
int port_cnt;
unsigned short ports[MAX_CONN];

/** error handling by print message
 * author: jiseong
 * date: 2020.11.10
 */
void error_handler(char *message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}

/** attach header to received message
 * format - hh:mm:ss.uuuuuu | <length> | message
 * author: jiseong
 * date: 2020.11.10
 */
void set_header(char (*message)[LOG_HEADER_LEN + BUF_SIZE + 1], int recv_len)
{
	struct timeval val;
	struct tm *ptm;
	
	gettimeofday(&val, NULL);
	ptm = localtime(&val.tv_sec);

	memset(*message, 0, LOG_HEADER_LEN);

	sprintf(*message, "%02d:%02d:%02d.%06ld | %3d |",
			ptm->tm_hour, ptm->tm_min, ptm->tm_sec, val.tv_usec, recv_len);
}


/** initialize address information for connection
 * author: jiseong
 * date: 2020.11.10
 */
void init_addr(struct sockaddr_in *serv_addr, unsigned short port) {
	memset(serv_addr, 0x00, sizeof(*serv_addr));
	serv_addr->sin_family = AF_INET;
	// IP Address may be changed
	serv_addr->sin_addr.s_addr = inet_addr("192.168.56.4");
	serv_addr->sin_port = htons(port);
}

/** get user input to initialize port number list, check conditions
 * e.g. port_cnt: 4, ports: [1111, 2222, 3333, 4444]
 * author: jiseong, hyokyung
 * date: 2020.11.10 ~ 2020.11.11
 */
void input_ports()
{
	scanf("%d", &port_cnt);
	if(port_cnt > MAX_CONN) {
		char s[40];
		sprintf(s, "# of connections cannot exceed %d", MAX_CONN);
		error_handler(s);
	}
	for(int i = 0; i < port_cnt; i++){
		scanf("%hu", &ports[i]);
	}

	for(int i = 0; i < port_cnt-1; i++){
		int counter = 0;
		for(int j = i+1; j < port_cnt; j++){
			if (ports[i] == ports[j]){
				counter++;			
			}	
		}	
		if(counter >= MAX_CONN_ON_PORT){
			char s[50];
			sprintf(s, "# of connections per port cannot exceed %d", MAX_CONN_ON_PORT);	
			error_handler(s);		
		}
	}
}

/** handle socket connection 
 * author: jiseong, hyokyung
 * date: 2020.11.10 ~ 2020.11.11
 */
void *socket_connection(void *arg){
	unsigned short port = *((unsigned short *)arg);

	// create socket
	int sock;
	struct sockaddr_in serv_addr;
	init_addr(&serv_addr, port);   // multi threads will open socket for all ports
	if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		error_handler("socket() error");

	// connection
	if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
		error_handler("connect() error");
	else 
		printf("open: %hu\n", port);

	// open file to record log
	char file_name[20];
	int log_fd;
	sprintf(file_name, "%hu-%d.txt", port, sock);
	log_fd = open(file_name, O_RDWR | O_CREAT | O_APPEND, 0644);	
	if(log_fd == -1)
		error_handler("open() error");

	int recv_len = 0;
	int recv_cnt;
	int at_count = 0;
	char message[LOG_HEADER_LEN + BUF_SIZE + 1];
	do {
		/** receive message and count 'at(@)' sign
		 * author: jiseong
		 * date: 2020.11.10
		 */
		recv_cnt = read(sock, &message[LOG_HEADER_LEN + recv_len], 1);
		if(recv_cnt == -1)
			error_handler("read() error");

		if(message[LOG_HEADER_LEN + recv_len] == '@')
			at_count++;

		recv_len += recv_cnt;
		if(recv_len == BUF_SIZE || at_count == 5) {
			set_header(&message, recv_len);
			message[LOG_HEADER_LEN + recv_len] = '\n';
			write(log_fd, message, LOG_HEADER_LEN + recv_len + 1);
			memset(message, 0, sizeof(message));
			recv_len = 0;
		}
	} while(at_count < 5);

	close(sock);
	pthread_exit(NULL);
}

/** run program
 * author: jiseong, hyokyung
 * date: 2020.11.11
 */
int main(int argc, char *argv[])
{
	pthread_t thread[MAX_CONN];

	while(1) {
		input_ports();

		/** handle multi-threaded connections
		 * author: hyokyung
		 * date: 2020.11.11
		 */
		for(int i = 0; i < port_cnt; i++){
			if (pthread_create(&thread[i], NULL, socket_connection, &ports[i]) != 0)
				error_handler("pthread_create() error");
		}

		for (int i = 0; i < port_cnt; i++){
			if (pthread_join(thread[i], NULL) != 0)
				error_handler("pthread_join() error");
		}

		printf("close\n"); // print message after all sockets are closed
	}

	return 0;
}	
