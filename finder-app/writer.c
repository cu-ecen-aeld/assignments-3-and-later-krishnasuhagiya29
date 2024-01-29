#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

int main(int argc, char *argv[]) {
	int fd;
	ssize_t bytes_written;
	int length = 0;

	// Setup syslog logging using LOG_USER
	openlog(NULL, 0, LOG_USER);
	// Check validity of the number of command line arguments
	if (argc != 3) {
		syslog(LOG_ERR, "Invalid Number of arguments: %d", argc);
		syslog(LOG_DEBUG, "Usage: ./writer.sh <file> <string>");
		return 1;
	}

	// Open the file specified by the user to write the string to
	const char *file_name = argv[1];
	fd = open(file_name, O_WRONLY | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);	// User: rw, Group: rw, Others: r
	if(fd == -1) {
		syslog(LOG_ERR, "Failed opening file %s with an error: %s", file_name, strerror(errno));
		return 1;
	}

	// Write the string specified by the user
	const char *buf = argv[2];
	// Get the length of the string
	length = strlen(buf);
	bytes_written = write (fd, buf, length);
	if (bytes_written == -1) {
		// Write failure
		syslog(LOG_ERR, "Failed writing to file %s with an error: %s", file_name, strerror(errno));
		closelog();
		close(fd);
		return 1;
	}
	else if (bytes_written != length) {
		// Partial write, errno is not set in this case
		syslog(LOG_ERR, "File %s partially written with %ld bytes out of %d bytes", file_name, bytes_written, length);
		closelog();
		close(fd);
		return 1;
	}
	else {
		// Write successful
		syslog(LOG_DEBUG, "Writing %s to %s", buf, file_name);
		closelog();
		close(fd);
	}

	return 0;
}