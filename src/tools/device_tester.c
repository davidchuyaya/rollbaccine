#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define READ_BUFFER_SIZE 4096

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: ./device_tester <filename> <read, write, overwrite, or append>\n");
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
            printf("%x ", (unsigned char)buffer[i]);
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

        char* write_buffer =
            "This is a larger chunk of text that will be written to the file. It can span multiple lines and contain any characters you want, including numbers (1234567890) and special symbols "
            "(!@#$%^&*()).";
        int len = write(file_pointer, write_buffer, strlen(write_buffer));
        if (len == -1) {
            printf("Error writing to file\n");
            ret = 1;
            goto cleanup;
        }
        printf("Wrote to file: %s\n", write_buffer);

        ret = fsync(file_pointer);
        if (ret == -1) {
            printf("Fsync error: %s\n", strerror(errno));
        }
        printf("Fsynced\n");
    } else if (strcmp(read_or_write, "overwrite") == 0 || strcmp(read_or_write, "append") == 0) {
        file_pointer = open(filename, O_CREAT | O_WRONLY, 777);
        if (file_pointer == -1) {
            printf("Error opening file, error: %d\n", errno);
            return 1;
        }

        char* write_buffer = "Write this first";
        int len = write(file_pointer, write_buffer, strlen(write_buffer));
        if (len == -1) {
            printf("Error writing to file\n");
            ret = 1;
            goto cleanup;
        }
        printf("Wrote this to file first: %s\n", write_buffer);

        // Seek on overwrite, don't seek on append
        if (strcmp(read_or_write, "overwrite") == 0) {
            lseek(file_pointer, 0, SEEK_SET);
            printf("Seeked to beginning of file\n");
        }

        write_buffer = "Write this second";
        len = write(file_pointer, write_buffer, strlen(write_buffer));
        if (len == -1) {
            printf("Error writing to file\n");
            ret = 1;
            goto cleanup;
        }
        printf("Wrote this to file second: %s\n", write_buffer);
    } else {
        printf("Expected 'read', 'write', 'overwrite', or 'append' as 2nd parameter\n");
        return 1;
    }

cleanup:
    close(file_pointer);
    return ret;
}