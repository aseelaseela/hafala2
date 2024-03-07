#ifndef SERVER_H
#define SERVER_H

#include <netinet/in.h> // sockaddr_in
#include <sys/socket.h> // socket functions
#include <sys/types.h>  // socket types
#include <signal.h>     // signal
#include <netdb.h>      // getnameinfo and getaddrinfo
#include <fcntl.h>      // fcntl
#include <sys/stat.h>   // mkdir

#define PORT "8080"      // Default port for the server
#define BACKLOG 100       // Maximum number of pending connections for TCP socket
#define BUFFER_SIZE 1024  // Buffer size for various operations

void send_error_response(int socket_client, const char *status);
void acquire_lock(int file_descriptor, struct flock *file_lock, int lock_type, const char *error_message);
void release_lock(int file_descriptor, struct flock *file_lock);
void process_post_request(int socket_client, char *base_path, char *request_buffer);
void process_get_request(int socket_client, char *base_path, char *request_buffer);
void handle_client(int socket_client, char *base_path);
void *get_ip_address_from_socket_address(struct sockaddr *socket_address);
void handle_child_process_termination(int signal);

#endif /* SERVER_H */
