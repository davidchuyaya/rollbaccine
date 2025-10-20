#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>

#define NUM_SECONDS 60
#define READ_BUFFER_SIZE 4096

int iops = 0;
int designated_thread_id = -1;

void* read_file(void* arg) {
    char* filename = (char*)arg;
    int file_pointer = open(filename, O_RDONLY | O_DIRECT, S_IRUSR);
    if (file_pointer == -1) {
        printf("Error opening file, error: %d\n", errno);
        return NULL;
    }

    // One of the threads will randomly be the last one to store its ID. This one will output the IOPS every second.
    pid_t tid = gettid();
    __atomic_store(&designated_thread_id, &tid, __ATOMIC_RELAXED);

    void* buffer;
    posix_memalign(&buffer, 4096, READ_BUFFER_SIZE); // Allocate aligned buffer for O_DIRECT
    struct timespec start, prev, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    prev = start;
    int prev_iops = 0, curr_iops = 0;

    do {
        int len = pread(file_pointer, buffer, READ_BUFFER_SIZE, 0);
        if (len == -1) {
            printf("Error reading file in thread %d\n", tid);
            break;
        }
        curr_iops = __atomic_add_fetch(&iops, 1, __ATOMIC_RELAXED);

        // If this is the designated thread, output IOPS every second.
        if (tid == designated_thread_id) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec - prev.tv_sec >= 1) {
                printf("Prev: %ld, Now: %ld, IOPS per second: %d\n", prev.tv_sec, now.tv_sec, curr_iops - prev_iops);
                prev = now;
                prev_iops = curr_iops;
            }
        }
    } while ((now.tv_sec - start.tv_sec) < NUM_SECONDS);

    close(file_pointer);
    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Usage: ./high_contention <filename> <read, write> <num threads>\n");
        return 1;
    }

    char* filename = argv[1];
    char* read_or_write = argv[2];
    int num_threads = atoi(argv[3]);
    pthread_t threads[num_threads];
    int ret = 0;

    // Read
    if (strcmp(read_or_write, "read") == 0) {
        printf("Running for %d seconds with %d threads reading...\n", NUM_SECONDS, num_threads);
        for (int i = 0; i < num_threads; i++) {
            if (pthread_create(&threads[i], NULL, read_file, (void*)filename) != 0) {
                printf("Error creating thread %d\n", i);
                return 1;
            }
        }
    }
    // Write "hello world"
    else if (strcmp(read_or_write, "write") == 0) {
        // TODO
    } else {
        printf("Expected 'read', 'write', 'overwrite', or 'append' as 2nd parameter\n");
        return 1;
    }

    // Wait for threads to finish
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    return ret;
}