#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{
    int ret = 0;

    struct thread_data* thread_func_args = (struct thread_data *)thread_param;

    openlog(NULL, 0, LOG_USER);

    // Wait for the specified time before attempting to obtain the mutex
    usleep(thread_func_args->wait_to_obtain_ms * 1000);

    // Obtain the mutex
    ret = pthread_mutex_lock(thread_func_args->mutex);
    if (ret != 0)
    {
        syslog(LOG_ERR, "%s failed with an error: %s", __func__, strerror(errno));
        closelog();
        return NULL;
    }


    // Wait for the specified time while holding the mutex
    usleep(thread_func_args->wait_to_release_ms * 1000);

    // Release the mutex
    ret = pthread_mutex_unlock(thread_func_args->mutex);
    if (ret != 0)
    {
        syslog(LOG_ERR, "%s failed with an error: %s", __func__, strerror(errno));
        closelog();
        return NULL;
    }

    // Set thread completion status to true
    thread_func_args->thread_complete_success = true;

    // Return thread data structure pointer
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    // Allocate memory for thread_data structure
    struct thread_data* thread_args = (struct thread_data*)malloc(sizeof(struct thread_data));
    if (thread_args == NULL) {
        return false; // Memory allocation failure
    }

    // Initialize the structure parameters 
    thread_args->mutex = mutex;
    thread_args->wait_to_obtain_ms = wait_to_obtain_ms;
    thread_args->wait_to_release_ms = wait_to_release_ms;
    thread_args->thread_complete_success = false;

    // Create the thread
    if (pthread_create(thread, NULL, threadfunc, (void*)thread_args) != 0) {
        free(thread_args);
        return false; // Thread creation failed
    }

    return true; // Thread created successfully
}

