#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include "systemcalls.h"

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{
    int ret = 0;
    // Setup syslog logging using LOG_USER
    openlog(NULL, 0, LOG_USER);
    ret = system(cmd);
    // Return checks
    if (ret == -1)
    {
        syslog(LOG_ERR, "system() call failed with an error: %s", strerror(errno));
        return false;
    }

    if (WIFSIGNALED (ret) && (WTERMSIG (ret) == SIGINT || WTERMSIG (ret) == SIGQUIT))
    {
        syslog(LOG_ERR, "system() call killed by signal: %d", WTERMSIG (ret));
        return false;
    }

    closelog();

    return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int status;
    pid_t pid;
    int i;

    // Setup syslog logging using LOG_USER
    openlog(NULL, 0, LOG_USER);

    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];

    if (command[0][0] != '/')
    {
        syslog(LOG_ERR, "The file path is not an absolute one.");
        return false;
    }

    pid = fork();
    if (pid == -1)
    {
        syslog(LOG_ERR, "fork() failed with an error: %s", strerror(errno));
        return false;
    }
    else if (pid == 0)
    {
        execv(command[0], command);
        syslog(LOG_ERR, "execv() failed with an error: %s", strerror(errno));
        return false;
    }

    if(waitpid(pid, &status, 0) == -1)
    {
        syslog(LOG_ERR, "waitpid() failed with an error: %s", strerror(errno));
        return false;
    }
    else if (WIFEXITED(status)) // Check WIFEXITED and WEXITSTATUS macros
    {
        if(WEXITSTATUS(status))
        {
            return false;
        }
    }

    closelog();

    va_end(args);

    return true;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    int status;
    int pid;
    va_start(args, count);
    char * command[count+1];
    int i;

    // Setup syslog logging using LOG_USER
    openlog(NULL, 0, LOG_USER);

    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];

    // The following code is referenced from https://stackoverflow.com/a/13784315/1446624

    int fd = open(outputfile, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    if (fd < 0)
    {
        syslog(LOG_ERR, "Failed opening output file %s with an error: %s", outputfile, strerror(errno));
        return false;
    }
    switch (pid = fork()) {
    case -1:
        syslog(LOG_ERR, "fork() failed with an error: %s", strerror(errno));
        return false;
    case 0:
        if (dup2(fd, 1) < 0)
        {
            syslog(LOG_ERR, "dup2() failed with an error: %s", strerror(errno));
            return false;
        }
        close(fd);
        execv(command[0], command);
        syslog(LOG_ERR, "execv() failed with an error: %s", strerror(errno));
        return false;
    default:
        close(fd);
    }

    if(waitpid(pid, &status, 0) == -1)
    {
        syslog(LOG_ERR, "waitpid() failed with an error: %s", strerror(errno));
        return false;
    }
    else if (WIFEXITED(status)) // Check WIFEXITED and WEXITSTATUS macros
    {
        if(WEXITSTATUS(status))
        {
            return false;
        }
    }

    closelog();

    va_end(args);

    return true;
}
