#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

int main(int argc, char *argv[]) {
	int fd;
	ssize_t nr;
	int length = 0;

	openlog(NULL, 0, LOG_USER);
	if (argc < 3) {
		syslog(LOG_ERR, "Invalid Number of arguments: %d", argc);
		syslog(LOG_DEBUG, "Usage: ./writer.sh <file> <string>");
		return 1;
	}

	const char *file_name = argv[1];
	fd = open(file_name, O_WRONLY | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
	if(fd == -1) {
		syslog(LOG_ERR, "Could not open %s", file_name);
		return 1;
	}

	// Write the string to file
	const char *buf = argv[2];
	length = strlen(buf);
	nr = write (fd, buf, length);
	if (nr == -1) {
		syslog(LOG_ERR, "Write to %s failed", file_name);
		return 1;
	}
	else if (nr != length) {
		syslog(LOG_ERR, "Write to %s failed", file_name);
		return 1;
	}
	else {
		syslog(LOG_DEBUG, "Writing %s to %s", buf, file_name);
	}

	return 0;
}

