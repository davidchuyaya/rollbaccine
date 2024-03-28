#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define READ_BUFFER_SIZE 256

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: ./device_tester <filename> <read, write, or clear>\n");
        return 1;
    }

    char* filename = argv[1];
    char* read_or_write = argv[2];
    int file_pointer;
    int ret = 0;

    // Read
    if (strcmp(read_or_write, "read") == 0) {
        file_pointer = open(filename, O_RDONLY);
        if (file_pointer == -1) {
            printf("Error opening file, error: %d\n", errno);
            return 1;
        }

        char buffer[READ_BUFFER_SIZE];

        lseek(file_pointer, 0, SEEK_SET);        
        int len = read(file_pointer, buffer, READ_BUFFER_SIZE);
        if (len == -1) {
            printf("Error reading file\n");
            ret = 1;
            goto cleanup;
        }

        printf("Read from file: %s\n", buffer);
        printf("Hex read from file: ");
        for (int i = 0; i < len; i++) {
            printf("%x ", (unsigned char) buffer[i]);
        }
        printf("\n");
    }
    // Write "hello world"
    else if (strcmp(read_or_write, "write") == 0) {
        file_pointer = open(filename, O_CREAT | O_WRONLY, 777);
        if (file_pointer == -1) {
            printf("Error opening file, error: %d\n", errno);
            return 1;
        }

        char* write_buffer = "NEVAHHH!";
        int len = write(file_pointer, write_buffer, strlen(write_buffer));
        if (len == -1) {
            printf("Error writing to file\n");
            ret = 1;
            goto cleanup;
        }

        printf("Wrote to file: %s\n", write_buffer);
    }
    else {
        printf("Expected 'read' or 'write' as 2nd parameter\n");
        return 1;
    }

    cleanup:
        close(file_pointer);
        return ret;
}