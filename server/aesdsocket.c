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
#include "queue.h"

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
bool term_sig_received = false;
int sock_fd, accept_fd = 0;
pthread_mutex_t mutex;
int file_fd = 0;

struct thread_data_s {
    bool        thread_completed;
    char        *client_ip;
    int         client_fd;
    pthread_t   thread_id;
    SLIST_ENTRY(thread_data_s) entries;
};

void setup_signal_handlers(void);

void signal_handler(int sig_no);

void alarm_handler(int sig_no);

void create_daemon(void);

void* thread_func(void* thread_params)
{
	bool packet_complete = false;
	char recv_buf[BUF_SIZE];
	int recv_bytes, bytes_written, bytes_sent, bytes_read = 0;
	int total_recv_bytes = 0;
    struct thread_data_s* thread_func_args = (struct thread_data_s *) thread_params;

    int updated_len = BUF_SIZE;
    char *full_buf = (char *)malloc(sizeof(char));
    memset(full_buf, 0, sizeof(char));
    if(full_buf == NULL)
    {
    	thread_func_args->thread_completed = true;
        close(file_fd);
    }

    // The following logic is updated based on the review comments from assignment 5 and code review in the class
    do
    {
        memset(recv_buf, 0, BUF_SIZE);
        recv_bytes = recv(thread_func_args->client_fd, recv_buf, BUF_SIZE, 0);
        if (recv_bytes == -1)
        {
            syslog(LOG_ERR, "Failed to recieve byte from client with fd:%d Error:%s\n", thread_func_args->client_fd, strerror(errno));
            thread_func_args->thread_completed = true;
            close(file_fd);
            exit(EXIT_FAILURE);
        }
        else if (recv_bytes > 0)
        {
            updated_len = strlen(full_buf) + strlen(recv_buf) + 1;
            char *updated_buf = realloc(full_buf, updated_len);
		    if (!updated_buf)
		    {
		        syslog(LOG_ERR, "Realloc failure");
		        thread_func_args->thread_completed = true;
		        close(file_fd);
		        exit(EXIT_FAILURE);
		    }

		    full_buf = updated_buf;
		    total_recv_bytes += recv_bytes;
		    strcpy(full_buf, recv_buf);
        }

	    if ((memchr(recv_buf, '\n', recv_bytes)) != NULL)
	    {
	        packet_complete = true;
	    }
    }while(!packet_complete);

	bytes_written = write(file_fd, full_buf, total_recv_bytes);
	if (bytes_written == -1) {
		syslog(LOG_ERR, "Failed writing to file with an error: %s\r\n", strerror(errno));
		close(file_fd);
		exit(EXIT_FAILURE);
	}
	else if (bytes_written != recv_bytes) {
		// Partial write, errno is not set in this case
		syslog(LOG_ERR, "File partially written with %d bytes out of %d bytes", bytes_written, recv_bytes);
		close(file_fd);
		exit(EXIT_FAILURE);
	}
	syslog(LOG_INFO, "Written %d bytes to the file\r\n", recv_bytes);
    pthread_mutex_unlock(&mutex);

	off_t set_offset = lseek(file_fd, 0, SEEK_SET);
	if (set_offset == -1)
	{
		syslog(LOG_ERR, "lseek() failed with an error: %s\r\n", strerror(errno));
		close(file_fd);
		exit(EXIT_FAILURE);
	}

	do
	{
		bytes_read = read(file_fd, recv_buf, BUF_SIZE);
		if (bytes_read == -1)
		{
			syslog(LOG_ERR, "read() failed with an error: %s\r\n", strerror(errno));
			close(file_fd);
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

    if(full_buf != NULL)
    {
    	free(full_buf);
    }
	close(thread_func_args->client_fd);	// parent doesn't need this

	syslog(LOG_INFO, "Closed connection from %s\r\n", thread_func_args->client_ip);
    thread_func_args->thread_completed = true;
    return thread_params;
}

void signal_handler(int sig_no) {
	term_sig_received = true;
	shutdown(sock_fd, SHUT_RDWR);
	syslog(LOG_INFO, "Caught Signal, exiting\r\n");
}

void alarm_handler(int sig_no) {
	time_t time_now ;
	struct tm *tm_time_now;
    char MY_TIME[TIMER_ARRAY_SIZE] = {'\0'};
    int bytes_written = 0;
    time( &time_now );

    //localtime() uses the time pointed by time_now,
    // to fill a tm_time_now structure with the
    // values that represent the
    // corresponding local time.

    tm_time_now = localtime( &time_now );

    // using strftime to display time
    strftime(MY_TIME, sizeof(MY_TIME), "timestamp: %A %B %d %H:%M:%S %Y\n", tm_time_now);
    if(pthread_mutex_lock(&mutex) != 0)
    {
		syslog(LOG_ERR, "Failed to lock mutex from %s\r\n", __func__);
    }
    else {

		bytes_written = write(file_fd, MY_TIME, sizeof(MY_TIME));
		if (bytes_written == -1) {
			syslog(LOG_ERR, "Failed writing to file with an error: %s\r\n", strerror(errno));
			close(file_fd);
			return;
		}
		if(pthread_mutex_unlock(&mutex) != 0)
		{
			syslog(LOG_ERR, "Failed to unlock mutex from %s\r\n", __func__);
			close(file_fd);
		}
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

	// Setup interval timer to print the timestamp every 10 seconds
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

int main(int argc, char *argv[]) {
	struct addrinfo hints, *servinfo = NULL;
	int yes=1;
	pthread_t thread;

	// Setup syslog logging using LOG_USER
	openlog(NULL, 0, LOG_USER);

    // Initialize mutex
    if (pthread_mutex_init(&mutex, NULL) != 0)
    {
        syslog(LOG_ERR, "getaddrinfo() failed with an error: %s\r\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

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

	setup_signal_handlers();

	if (listen(sock_fd, BACKLOG) == -1) {
		syslog(LOG_ERR, "listen() failed with an error: %s\r\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Initialize the link list
    SLIST_HEAD(slist_head, thread_data_s) head;
    SLIST_INIT(&head);

	file_fd = open(FILE_NAME, O_CREAT | O_RDWR | O_APPEND, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
	if(file_fd == -1) {
		syslog(LOG_ERR, "Failed opening file %s with an error: %s", FILE_NAME, strerror(errno));
		exit(EXIT_FAILURE);
	}
	syslog(LOG_INFO, "File %s opened for dumping the packet data\r\n", FILE_NAME);

	while(!term_sig_received) {  // main accept() loop
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

		struct thread_data_s *thread_struct = (struct thread_data_s *) malloc(sizeof(struct thread_data_s));
        if (!thread_struct)
        {
            syslog(LOG_ERR, "Failed to allocate memory for thread structure\r\n");
            exit(EXIT_FAILURE);
        }
        thread_struct->client_ip = client_ip;
        thread_struct->client_fd = accept_fd;
        thread_struct->thread_completed = false;        
        int thread_id = pthread_create(&thread, NULL, thread_func, thread_struct);        
        if (thread_id != 0)
        {
            syslog(LOG_ERR, "Error creating new thread");
            free(thread_struct);
            exit(EXIT_FAILURE);
        }
        thread_struct->thread_id = thread;
        SLIST_INSERT_HEAD(&head, thread_struct, entries);

        struct thread_data_s *thread_ptr = NULL;
        struct thread_data_s *next_thread = NULL;
        SLIST_FOREACH_SAFE(thread_ptr, &head, entries, next_thread)
        {
	        if (thread_ptr->thread_completed)
	        {
	            syslog(LOG_INFO, "Thread complete, joining");
	            int id = pthread_join(thread_ptr->thread_id, NULL);
	            if (id != 0)
	            {
	                syslog(LOG_ERR, "Failure joining thread");
	                exit(EXIT_FAILURE);
	            }
	            SLIST_REMOVE(&head, thread_ptr, thread_data_s, entries);
	            free(thread_ptr);
	        }
	    }
	}

    while (!SLIST_EMPTY(&head))
    {
        struct thread_data_s *thread_rm = SLIST_FIRST(&head);
        pthread_join(thread_rm->thread_id, NULL);
        SLIST_REMOVE_HEAD(&head, entries);
        free(thread_rm);
    }

    pthread_mutex_destroy(&mutex);
	//free(recv_buf);
	close(accept_fd);
	close(sock_fd);
	remove(FILE_NAME);
	closelog();
	exit(EXIT_SUCCESS);

    close(file_fd);
	closelog();

	return 0;
}
