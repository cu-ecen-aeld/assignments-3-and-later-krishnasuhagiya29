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
#include <time.h>
#include <sys/time.h>
#include <pthread.h>

#define PORT "9000"  // the port users will be connecting to
#define DOMAIN	PF_INET
#define TYPE	SOCK_STREAM
#define PROTOCOL	0
#define BACKLOG 10	 // how many pending connections queue will hold
#define BUF_SIZE	1024
#define FILE_NAME	"/var/tmp/aesdsocketdata"
#define TEN_SECONDS	10
#define TIMER_ARRAY_SIZE	50

bool run_as_daemon = false;
int sock_fd, accept_fd = 0;
char *recv_buf = NULL;
pthread_mutex_t mutex;

void signal_handler(int sig_no);

void setup_signal_handlers(void);

void create_daemon(void);

int main(int argc, char *argv[]) {
	struct addrinfo hints, *servinfo = NULL;
	int fd = 0;
	int yes=1;

	// Setup syslog logging using LOG_USER
	openlog(NULL, 0, LOG_USER);

    // Initialize mutex
    if (pthread_mutex_init(&mutex, NULL) != 0)
    {
        syslog(LOG_ERR, "getaddrinfo() failed with an error: %s\r\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

	setup_signal_handlers();

	if ((argc == 2) && strcmp(argv[1], "-d") == 0) {
		run_as_daemon = true;
		syslog(LOG_INFO, "Running aesd socket as daemon\r\n");
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = DOMAIN;
	hints.ai_socktype = TYPE;
	hints.ai_flags = AI_PASSIVE;

	int err = getaddrinfo(NULL, PORT, &hints, &servinfo);

	if (err != 0) {
		syslog(LOG_ERR, "getaddrinfo() failed with an error: %s\r\n", strerror(errno));
		freeaddrinfo(servinfo);
		exit(EXIT_FAILURE);
	}

	if(servinfo == NULL)
	{
		syslog(LOG_ERR, "servinfo is NULL\r\n");
		exit(EXIT_FAILURE);
	}

	sock_fd = socket(servinfo->ai_family, servinfo->ai_socktype, PROTOCOL);
	if (sock_fd == -1)
	{
		syslog(LOG_ERR, "socket() failed with an error: %s\r\n", strerror(errno));
		freeaddrinfo(servinfo);
		exit(EXIT_FAILURE);
	}

	syslog(LOG_INFO, "Socket created successfully with fd: %d\r\n", sock_fd);

	// Running the application numtiple times without the reuse code below results into: bind() failed with an error: Address already in use#015
	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		syslog(LOG_ERR, "setsockopt() failed with an error: %s\r\n", strerror(errno));
		freeaddrinfo(servinfo);
		exit(EXIT_FAILURE);
	}	

	if (bind(sock_fd, servinfo->ai_addr, sizeof(struct addrinfo)) == -1) {
		syslog(LOG_ERR, "bind() failed with an error: %s\r\n", strerror(errno));
		freeaddrinfo(servinfo);
		exit(EXIT_FAILURE);
	}

	syslog(LOG_INFO, "Socket bound successfully \r\n");

	if (servinfo != NULL)
	{
		freeaddrinfo(servinfo);
		syslog(LOG_INFO, "servinfo freed \r\n");
	}

	if (run_as_daemon == true)
	{
		create_daemon();
	}

	if (listen(sock_fd, BACKLOG) == -1) {
		syslog(LOG_ERR, "listen() failed with an error: %s\r\n", strerror(errno));
		exit(EXIT_FAILURE);
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
		inet_ntop(PF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN );
		syslog(LOG_INFO, "Accepted connection from %s\r\n", client_ip);

		fd = open(FILE_NAME, O_CREAT | O_RDWR | O_APPEND, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
		if(fd == -1) {
			syslog(LOG_ERR, "Failed opening file %s with an error: %s", FILE_NAME, strerror(errno));
			exit(EXIT_FAILURE);
		}
		syslog(LOG_INFO, "File %s opened for dumping the packet data\r\n", FILE_NAME);

		do
		{
			recv_bytes = recv(accept_fd, recv_buf, BUF_SIZE, 0);
			if (recv_bytes == -1)
			{
				syslog(LOG_ERR, "recv() failed with an error: %s\r\n", strerror(errno));
				exit(EXIT_FAILURE);
			}

			bytes_written = write(fd, recv_buf, recv_bytes);
			if (bytes_written == -1) {
				syslog(LOG_ERR, "Failed writing to file with an error: %s\r\n", strerror(errno));
				close(fd);
				exit(EXIT_FAILURE);
			}
			else if (bytes_written != recv_bytes) {
				// Partial write, errno is not set in this case
				syslog(LOG_ERR, "File partially written with %d bytes out of %d bytes", bytes_written, recv_bytes);
				close(fd);
				exit(EXIT_FAILURE);
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
			exit(EXIT_FAILURE);
		}

		do
		{
			bytes_read = read(fd, recv_buf, BUF_SIZE);
			if (bytes_read == -1)
			{
				syslog(LOG_ERR, "read() failed with an error: %s\r\n", strerror(errno));
				close(fd);
				exit(EXIT_FAILURE);
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

	closelog();

	return 0;
}

void signal_handler(int sig_no) {
	if ((sig_no == SIGINT) || (sig_no == SIGTERM))
	{
		syslog(LOG_INFO, "Caught Signal, exiting\r\n");
		free(recv_buf);
		close(accept_fd);
		close(sock_fd);
		remove(FILE_NAME);
		closelog();
		exit(EXIT_SUCCESS);
	}
}

// TODO: Make the alarm_handler smaller
void alarm_handler(int sig_no) {
	time_t time_now ;
	struct tm *tm_time_now;
    char MY_TIME[TIMER_ARRAY_SIZE];
    int bytes_written = 0;
    time( &time_now );

    //localtime() uses the time pointed by time_now,
    // to fill a tm_time_now structure with the
    // values that represent the
    // corresponding local time.

    tm_time_now = localtime( &time_now );

    // using strftime to display time
    strftime(MY_TIME, sizeof(MY_TIME), "%A %B %d %H:%M:%S %Y\n", tm_time_now);
    printf("%s\n", MY_TIME);
    if(pthread_mutex_lock(&mutex) != 0)
    {
		syslog(LOG_ERR, "Failed to lock mutex from %s\r\n", __func__);
    }
    else {
		int fd = open(FILE_NAME, O_CREAT | O_RDWR | O_APPEND, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
		if(fd == -1) {
			syslog(LOG_ERR, "Failed opening file %s with an error: %s from %s", FILE_NAME, strerror(errno), __func__);
			exit(EXIT_FAILURE);
		}

		bytes_written = write(fd, MY_TIME, sizeof(MY_TIME));
		if (bytes_written == -1) {
			syslog(LOG_ERR, "Failed writing to file with an error: %s\r\n", strerror(errno));
			close(fd);
			exit(EXIT_FAILURE);
		}
		if(pthread_mutex_unlock(&mutex) != 0)
		{
			syslog(LOG_ERR, "Failed to unlock mutex from %s\r\n", __func__);
			close(fd);
		}
		close(fd);
    }
}

void setup_signal_handlers(void) {
	struct itimerval delay;
	int ret;
	if(signal(SIGINT, signal_handler) == SIG_ERR) {
		syslog(LOG_ERR, "signal() for SIGINT failed with an error: %s\r\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(signal(SIGTERM, signal_handler) == SIG_ERR) {
		syslog(LOG_ERR, "signal() for SIGTERM failed with an error: %s\r\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	delay.it_value.tv_sec = TEN_SECONDS;
	delay.it_value.tv_usec = 0;
	delay.it_interval.tv_sec = delay.it_value.tv_sec;
	delay.it_interval.tv_usec = delay.it_value.tv_usec;
	ret = setitimer (ITIMER_REAL, &delay, NULL);
	if (ret) {
		syslog(LOG_ERR, "setitimer() failed with an error: %s\r\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(signal(SIGALRM, alarm_handler) == SIG_ERR) {
		syslog(LOG_ERR, "signal() for SIGALRM failed with an error: %s\r\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

void create_daemon(void) {
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
		syslog(LOG_ERR, "Unable to create a session\r\n");
		exit(EXIT_FAILURE);
	}
	if ((chdir("/")) < 0) {
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