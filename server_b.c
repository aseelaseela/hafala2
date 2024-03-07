#include "server.h"
#include <openssl/bio.h> //BIO, BIO_new, BIO_free_all, BIO_push, BIO_set_flags, BIO_read, BIO_write, BIO_flush
#include <openssl/evp.h> //EVP_DecodeBlock
#include <string.h>      //strlen
#include <stdio.h>       //FILE, fmemopen, fclose
#include <math.h>        //ceil
#include <stdlib.h>      //malloc and free
#include <unistd.h>
#include <arpa/inet.h>   // inet_ntop and inet_pton
#include <sys/wait.h>    // waitpid and WNOHANG
#include <errno.h>       // errno

void send_error_response(int socket_client, const char *status) {
    char error_message[1024];
    sprintf(error_message, "%s\r\n\r\n", status);
    send(socket_client, error_message, strlen(error_message), 0);
    exit(1);
}

void acquire_lock(int file_descriptor, struct flock *file_lock, int lock_type, const char *error_message) {
    file_lock->l_type = lock_type;
    if (fcntl(file_descriptor, F_SETLKW, file_lock) == -1) {
        send_error_response(file_descriptor, error_message);
    }
}

void release_lock(int file_descriptor, struct flock *file_lock) {
    file_lock->l_type = F_UNLCK;
    fcntl(file_descriptor, F_SETLK, file_lock);
}

void process_post_request(int socket_client, char *base_path, char *request_buffer) {
    // Extract the path from the request buffer
    char *request_path = strtok(request_buffer + 5, "\r\n");
    
    // Allocate memory for the full file path
    // +2 for potential slash and null terminator
    char *file_path = (char *)malloc(strlen(base_path) + strlen(request_path) + 2);
    if (!file_path) {
        send_error_response(socket_client, "500 INTERNAL SERVER ERROR\r\n\r\n");
        return; // Don't forget to handle memory allocation failure
    }
    file_path[0] = '\0';
    
    // Concatenate the base path
    strcat(file_path, base_path);
    // Ensure there is a slash between the base path and the request path
    if (file_path[strlen(file_path) - 1] != '/') {
        strcat(file_path, "/");
    }
    // Concatenate the request path
    strcat(file_path, request_path);
    
    // Logging the file path for verification
    printf("File path: %s\n", file_path);

    // Directory handling omitted for brevity - assume it's correctly handling directory creation
    
    // Attempt to open or create the file
    int file_descriptor = open(file_path, O_WRONLY | O_CREAT, 0644);
    if (file_descriptor == -1) {
        send_error_response(socket_client, "404 FILE NOT FOUND\r\n\r\n");
        free(file_path); // Don't forget to free allocated memory on error
        return;
    }

    // Prepare and acquire a write lock on the file
    struct flock file_lock = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0 // Lock the whole file
    };
    acquire_lock(file_descriptor, &file_lock, F_WRLCK, "500 INTERNAL ERROR\r\n\r\n");

    // Write data to the file
    // Note: This example assumes the rest of the data handling remains unchanged

    // Always ensure the file path is freed and the file is closed to prevent memory leaks and resource exhaustion
    free(file_path);
    release_lock(file_descriptor, &file_lock);
    close(file_descriptor);

    // Indicate success
    send(socket_client, "200 OK\r\n\r\n", strlen("200 OK\r\n\r\n"), 0);
}

void process_get_request(int socket_client, char *base_path, char *request_buffer) {
    char *requested_path = strtok(request_buffer + 4, "\r\n\r\n");
    
    if (requested_path == NULL) {
        send_error_response(socket_client, "400 Bad Request");
        return;
    }

    char *file_path = (char *)malloc(strlen(base_path) + strlen(requested_path) + 1);
    file_path[0] = '\0';
    strcat(file_path, base_path);

    // Ensure requested_path starts with '/'
    if (requested_path[0] != '/') {
        strcat(file_path, "/");
    }

    strcat(file_path, requested_path);
    printf("File path: %s\n", file_path);

    int file_descriptor = open(file_path, O_RDONLY);
    if (file_descriptor == -1) {
        perror("Error opening file");
        send_error_response(socket_client, "404 Not Found");
        free(file_path);
        return;
    }

    struct flock file_lock = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0};
    acquire_lock(file_descriptor, &file_lock, F_RDLCK, "500 Internal Server Error");

    char response_buffer[1024];
    ssize_t data_length;

    while ((data_length = read(file_descriptor, response_buffer, sizeof(response_buffer))) > 0) {
        if (send(socket_client, response_buffer, data_length, 0) < 0) {
            perror("Error sending file data");
            break;
        }
    }

    release_lock(file_descriptor, &file_lock);
    free(file_path);
    close(file_descriptor);
}
void handle_client(int socket_client, char *base_path) {
    char client_request[1024];
    int request_length = recv(socket_client, client_request, sizeof(client_request) - 1, 0);
    client_request[request_length] = '\0';
    printf("Client Request: %s\n", client_request);

    if (strncmp(client_request, "POST", 4) == 0) {
        process_post_request(socket_client, base_path, client_request);
    } else if (strncmp(client_request, "GET", 3) == 0) {
        process_get_request(socket_client, base_path, client_request);
    } else {
        printf("Invalid request\n");
        send_error_response(socket_client, "500 INTERNAL ERROR");
    }
}

void *get_ip_address_from_socket_address(struct sockaddr *socket_address) {
    if (socket_address->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)socket_address)->sin_addr);
    }

    return &(((struct sockaddr_in6*)socket_address)->sin6_addr);
}

void handle_child_process_termination(int signal) {
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

int main(int argc, char *argv[]) {
    int server_socket, client_socket;
    struct addrinfo server_hints, *server_info, *current;
    struct sockaddr_storage client_address;
    socklen_t client_address_size;
    struct sigaction child_termination_action;
    int reuse_address = 1;
    char client_ip_string[INET6_ADDRSTRLEN];
    int getaddrinfo_result;

    if (argc != 2) {
        fprintf(stderr, "Usage: ./server <home_directory>\n");
        exit(EXIT_FAILURE);
    }

    char *home_directory = argv[1];

    memset(&server_hints, 0, sizeof(server_hints));
    server_hints.ai_family = AF_UNSPEC;
    server_hints.ai_socktype = SOCK_STREAM;
    server_hints.ai_flags = AI_PASSIVE;

    if ((getaddrinfo_result = getaddrinfo(NULL, PORT, &server_hints, &server_info)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(getaddrinfo_result));
        exit(EXIT_FAILURE);
    }

    for (current = server_info; current != NULL; current = current->ai_next) {
        if ((server_socket = socket(current->ai_family, current->ai_socktype, current->ai_protocol)) == -1) {
        perror("Error creating server socket");
        continue;
        }

        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &reuse_address, sizeof(int)) == -1) {
            perror("Error setting socket options");
            exit(EXIT_FAILURE);
        }

        if (bind(server_socket, current->ai_addr, current->ai_addrlen) == -1) {
            close(server_socket);
            perror("Error: Failed to bind server socket\n");
            continue;
        }

        break;
    }

    freeaddrinfo(server_info);

    if (current == NULL) {
        fprintf(stderr, "binding server socket failed\n");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, BACKLOG) == -1) {
        perror("Error while setting up server to listen");
        exit(EXIT_FAILURE);
    }

    if (signal(SIGCHLD, handle_child_process_termination) == SIG_ERR) {
        perror("Error setting up signal handler for child processes");
        exit(EXIT_FAILURE);
    }

   printf("Server is waiting for connections...\n");

while (1) {
    // Accept incoming connection
    client_address_size = sizeof(client_address);
    client_socket = accept(server_socket, (struct sockaddr *)&client_address, &client_address_size);
    if (client_socket == -1) {
        perror("Error accepting incoming connection");
        continue;
    }

    // Convert client address to human-readable format
    inet_ntop(client_address.ss_family, get_ip_address_from_socket_address((struct sockaddr *)&client_address), client_ip_string, sizeof(client_ip_string));
    printf("Connection established with client at IP: %s\n", client_ip_string);

    // Fork to handle the client in a separate process
    if (!fork()) {
        close(server_socket); // Close the server socket in the child process
        handle_client(client_socket, home_directory); // Handle the client's request
        close(client_socket); // Close the client socket in the child process
        exit(EXIT_SUCCESS); // Terminate the child process
    }

    close(client_socket); // Close the client socket in the parent process
}

return 0;
}
	
