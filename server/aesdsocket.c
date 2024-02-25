#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>

#define PORT "9000"  // the port users will be connecting to
#define DOMAIN	PF_INET
#define TYPE	SOCK_STREAM
#define PROTOCOL	0
#define BACKLOG 10	 // how many pending connections queue will hold
#define BUF_SIZE	1024
#define FILE_NAME	"/var/tmp/aesdsocketdata"

bool run_as_daemon = false;
int sock_fd;
char *recv_buf;

void _daemon(void);

void signal_handler(int sig_no);

int main(int argc, char *argv[]) {
	struct addrinfo hints, *servinfo = NULL;
	int accept_fd, fd = 0;
	int yes=1;

	// Setup syslog logging using LOG_USER
	openlog(NULL, 0, LOG_USER);

	if(signal(SIGINT, signal_handler) == SIG_ERR) {
		syslog(LOG_ERR, "signal() for SIGINT failed with an error: %s\r\n", strerror(errno));
		exit(1);
	}

	if(signal(SIGTERM, signal_handler) == SIG_ERR) {
		syslog(LOG_ERR, "signal() for SIGTERM failed with an error: %s\r\n", strerror(errno));
		exit(1);
	}

	if ((argc == 2) && strcmp(argv[1], "-d") == 0) {
		run_as_daemon = true;
		syslog(LOG_INFO, "Running aesd socket as daemon\r\n");
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = DOMAIN;
	hints.ai_socktype = TYPE;
	hints.ai_protocol = PROTOCOL;

	if ((getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
		syslog(LOG_ERR, "getaddrinfo() failed with an error: %s\r\n", strerror(errno));
		freeaddrinfo(servinfo);
		exit(1);
	}

	if(servinfo == NULL)
	{
		syslog(LOG_ERR, "servinfo is NULL\r\n");
		exit(1);
	}

	sock_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
	if (sock_fd == -1)
	{
		syslog(LOG_ERR, "socket() failed with an error: %s\r\n", strerror(errno));
		freeaddrinfo(servinfo);
		exit(1);
	}

	syslog(LOG_INFO, "Socket created successfully with fd: %d\r\n", sock_fd);

	// Running the application numtiple times without the reuse code below results into: bind() failed with an error: Address already in use#015
	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		syslog(LOG_ERR, "setsockopt() failed with an error: %s\r\n", strerror(errno));
		freeaddrinfo(servinfo);
		exit(1);
	}	

	if (bind(sock_fd, servinfo->ai_addr, sizeof(struct addrinfo)) == -1) {
		syslog(LOG_ERR, "bind() failed with an error: %s\r\n", strerror(errno));
		freeaddrinfo(servinfo);
		exit(1);
	}

	syslog(LOG_INFO, "Socket bound successfully \r\n");

	if (servinfo != NULL)
	{
		freeaddrinfo(servinfo);
		syslog(LOG_INFO, "servinfo freed \r\n");
	}

	if (run_as_daemon == true)
	{
		_daemon();
	}

	if (listen(sock_fd, BACKLOG) == -1) {
		syslog(LOG_ERR, "listen() failed with an error: %s\r\n", strerror(errno));
		exit(1);
	}

	bool packet_complete = false;
	recv_buf = (char *)malloc(BUF_SIZE * sizeof(char));
	int recv_bytes, bytes_written, bytes_read, bytes_sent = 0;

	while(1) {  // main accept() loop
		struct sockaddr_in client_addr;
		socklen_t client_addr_len = sizeof(client_addr);
		accept_fd = accept(sock_fd, (struct sockaddr *)&client_addr, &client_addr_len);
		if (accept_fd == -1) {
			syslog(LOG_ERR, "accept() failed with an error: %s\r\n", strerror(errno));
			continue;
		}

		char client_ip[INET_ADDRSTRLEN];
		inet_ntop(PF_INET,
			&(client_addr.sin_addr),
			client_ip, INET_ADDRSTRLEN );
		syslog(LOG_INFO, "Accepted connection from %s\r\n", client_ip);

		fd = open(FILE_NAME, O_CREAT | O_RDWR | O_APPEND, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
		if(fd == -1) {
			syslog(LOG_ERR, "Failed opening file %s with an error: %s", FILE_NAME, strerror(errno));
			exit(1);
		}
		syslog(LOG_INFO, "File %s opened for dumping the packet data\r\n", FILE_NAME);

		do
		{
			memset(recv_buf, 0, BUF_SIZE);
			recv_bytes = recv(accept_fd, recv_buf, BUF_SIZE, 0);
			if (recv_bytes == -1)
			{
				syslog(LOG_ERR, "recv() failed with an error: %s\r\n", strerror(errno));
				exit(1);
			}

			bytes_written = write(fd, recv_buf, recv_bytes);
			if (bytes_written == -1) {
				syslog(LOG_ERR, "Failed writing to file with an error: %s\r\n", strerror(errno));
				close(fd);
				exit(1);
			}
			else if (bytes_written != recv_bytes) {
				// Partial write, errno is not set in this case
				syslog(LOG_ERR, "File partially written with %d bytes out of %d bytes", bytes_written, recv_bytes);
				close(fd);
				exit(1);
			}
			syslog(LOG_INFO, "Written %d bytes to the file\r\n", recv_bytes);

			if(NULL != (memchr(recv_buf, '\n', recv_bytes)))
			{
				packet_complete = true;
			}
		} while(!packet_complete);

		packet_complete = false;
		off_t set_offset = lseek(fd, 0, SEEK_SET);
		if (set_offset == -1)
		{
			syslog(LOG_ERR, "lseek() failed with an error: %s\r\n", strerror(errno));
			close(fd);
			exit(1);
		}

		do
		{
			memset(recv_buf, 0, BUF_SIZE);
			bytes_read = read(fd, recv_buf, BUF_SIZE);
			if (bytes_read == -1)
			{
				syslog(LOG_ERR, "read() failed with an error: %s\r\n", strerror(errno));
				close(fd);
				exit(1);
			}

			if (bytes_read > 0)
			{
				bytes_sent = send(accept_fd, recv_buf, bytes_read, 0);
				if (bytes_sent != bytes_read)
				{
					syslog(LOG_ERR, "send() failed with an error: %s\r\n", strerror(errno));
				}
				syslog(LOG_INFO, "Sent %d bytes to the client\r\n", bytes_sent);

			}

		} while(bytes_read > 0);

		close(fd);
		close(accept_fd);	// parent doesn't need this

		syslog(LOG_INFO, "Closed connection from %s\r\n", client_ip);
	}

	free(recv_buf);

	return 0;
}

void signal_handler(int sig_no) {
	if ((sig_no == SIGINT) || (sig_no == SIGTERM))
	{
		syslog(LOG_INFO, "Caught Signal, exiting\r\n");
		free(recv_buf);
		close(sock_fd);
		remove(FILE_NAME);
		closelog();
		exit(0);
	}
}

void _daemon(void) {
	// PID: Process ID
	// SID: Session ID
	pid_t pid, sid;
	int fd = 0;

	fflush(stdout);
	pid = fork(); // Fork off the parent process
	if (pid < 0) {
		syslog(LOG_ERR, "Unable to fork\r\n");
		exit(EXIT_FAILURE);
	}
	if (pid > 0) {
		syslog(LOG_ERR, "Exiting\r\n");
		exit(EXIT_SUCCESS);
	}

	syslog(LOG_INFO, "Child created\r\n");

	// Create a SID for child
	sid = setsid();
	if (sid < 0) {
	// FAIL
		syslog(LOG_ERR, "Unable to create a session\r\n");
		exit(EXIT_FAILURE);
	}
	if ((chdir("/")) < 0) {
	// FAIL
		syslog(LOG_ERR, "Unable to change working directory\r\n");
		exit(EXIT_FAILURE);
	}
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	fd = open("/dev/null", O_WRONLY);
	if (fd == -1)
	{
		syslog(LOG_ERR, "open failed with an error: %s\r\n", strerror(errno));
		close(fd);
	}
	if (dup2(fd, STDIN_FILENO) == -1)
	{
		syslog(LOG_ERR, "dup2 for STDIN_FILENO failed with an error: %s\r\n", strerror(errno));
		close(fd);
	}
	if (dup2(fd, STDOUT_FILENO) == -1)
	{
		syslog(LOG_ERR, "dup2 for STDOUT_FILENO failed with an error: %s\r\n", strerror(errno));
		close(fd);
	}
	if (dup2(fd, STDERR_FILENO) == -1)
	{
		syslog(LOG_ERR, "dup2 for STDERR_FILENO failed with an error: %s\r\n", strerror(errno));
		close(fd);
	}
	close(fd);
}