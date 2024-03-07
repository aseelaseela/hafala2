#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/bio.h> 
#include <openssl/evp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <math.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <sys/stat.h>


#define PORT "8080"
#define BUFFER_SIZE 1024
#define MAX_HOST_SIZE 1024


size_t base64_decoded_length(const char* encoded_string, size_t length) {
 int padding = 0;
 // Check for padding in the last one or two characters
 if (encoded_string[length - 1] == '=' && encoded_string[length - 2] == '=') {
 padding = 2;
 } else if (encoded_string[length - 1] == '=') {
 padding = 1;
 }
 // Calculate the decoded length
 return (length * 3) / 4 - padding;
}


// Function to encode binary data to Base64
int base64_encode(const char* input, char** buffer, int length) {
 FILE* stream;
 int encoded_size=4*ceil((double)(length/3));
 *buffer = (char*)malloc(encoded_size+1);
 stream = fmemopen(*buffer,encoded_size+1,"w");
 
 // Create a BIO object for encoding
 BIO* bio;
 bio = BIO_new_fp(stream,BIO_NOCLOSE);
 BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

 // Create a memory BIO to hold the encoded data
 BIO* mem_bio;
 mem_bio = BIO_new(BIO_f_base64());
 bio = BIO_push(bio, mem_bio);

 // Write the input data to the BIO
 BIO_write(bio, input, length);
 BIO_flush(bio);

 // Clean up
 BIO_free_all(bio);
 fclose(stream);

 return 0;
}

// Function to decode Base64 to binary data
int base64_decoded(char *encoded_base64_string, char **decoded_buffer, size_t *decoded_length) {
 BIO *bio, *b64;

 // Calculate the length of the decoded buffer
 *decoded_length = base64_decoded_length(encoded_base64_string, strlen(encoded_base64_string));
 *decoded_buffer = (unsigned char *)malloc(*decoded_length + 1);

 if (*decoded_buffer == NULL) {
 // Memory allocation error
 return -1;
 }

 // Set up BIO chain for base64 decoding
 bio = BIO_new_mem_buf(encoded_base64_string, -1);
 b64 = BIO_new(BIO_f_base64());
 bio = BIO_push(b64, bio);

 // Configure BIO for decoding
 BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); 

 // Perform decoding
 *decoded_length = BIO_read(bio, *decoded_buffer, strlen(encoded_base64_string));
 (*decoded_buffer)[*decoded_length] = '\0'; 

 // Cleanup
 BIO_free_all(bio);

 return 0; // Success
}
bool endsWithString(const char *fullString, const char *ending) {
 if ((!fullString || !ending) || (strlen(fullString) < strlen(ending)))
 return false;
 return strncmp(fullString + strlen(fullString) - strlen(ending), ending, strlen(ending)) == 0;
}

bool handleHttpResponse(const char *httpResponse) {
 if (httpResponse == NULL) {
 fprintf(stderr, "Error: Invalid input - httpResponse is NULL\n");
 return false;
 }

 if (strstr(httpResponse, "500 Internal Server Error") != NULL) {
 printf("Server Error (500): Internal server error occurred.\n");
 } else if (strstr(httpResponse, "404 Not Found") != NULL) {
 printf("Client Error (404): The requested resource was not found.\n");
 return false;
 }

 return true;
}

void *getIPAddressFromSockAddr(struct sockaddr *sa) {
 if (sa == NULL) {
 fprintf(stderr, "Error: Invalid input - sa is NULL\n");
 return NULL;
 }

 if (sa->sa_family == AF_INET) {
 return &(((struct sockaddr_in *)sa)->sin_addr);
 } else if (sa->sa_family == AF_INET6) {
 return &(((struct sockaddr_in6 *)sa)->sin6_addr);
 } else {
 fprintf(stderr, "Error: Unknown address family type\n");
 return NULL;
 }
}


void downloadFileFromServer(char* remoteFilePath, int socketFd) {
    int bytesRead;
    char buffer[BUFFER_SIZE];

    printf("Sending GET request for: %s\n", remoteFilePath);

    // Construct the GET request
    snprintf(buffer, BUFFER_SIZE, "GET %s\r\n\r\n", remoteFilePath);

    // Send the GET request to the server
    if (write(socketFd, buffer, strlen(buffer)) < 0) {
        perror("Error writing GET request to the server");
        exit(EXIT_FAILURE);
    }

    printf("GET request sent.\n");

    char* directory = strdup(remoteFilePath);
    char* lastSlash = strrchr(directory, '/');
    if (lastSlash != NULL) {
        *lastSlash = '\0';
        if (mkdir(directory, 0777) < 0) {
            if (errno != EEXIST) {
                perror("Error creating directory for file");
                exit(EXIT_FAILURE);
            }
        }
    }

    char* localFilePath = strrchr(remoteFilePath, '/');
    if (localFilePath != NULL) {
        localFilePath++;  // Move past the last '/'
    } else {
        localFilePath = remoteFilePath;  // Use the entire path if no '/'
    }

    char* localFilePathFull = (char*)malloc(strlen(localFilePath) + strlen(directory) + 2);
    sprintf(localFilePathFull, "%s/%s", directory, localFilePath);

    int fileDescriptor = open(localFilePathFull, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fileDescriptor < 0) {
        perror("Error opening file for writing");
        free(directory);
        free(localFilePathFull);
        exit(EXIT_FAILURE);
    }

    // Receive and write the file content in chunks
    while (1) {
        bytesRead = recv(socketFd, buffer, BUFFER_SIZE, 0);

        if (bytesRead < 0) {
            perror("Error receiving data from the server");
            exit(EXIT_FAILURE);
        }

        if (bytesRead == 0) {
            break;  // End of file
        }

        if (!handleHttpResponse(buffer)) {
            fprintf(stderr, "Error handling HTTP response from the server\n");
            free(directory);
            free(localFilePathFull);
            return;
        }

        // Decode the base64-encoded content
        char* decodedContent;
        size_t decodedLength = bytesRead;

        if (base64_decoded((char*)buffer, &decodedContent, &decodedLength) != 0) {
            perror("Error decoding the content of the file");
            exit(EXIT_FAILURE);
        }

        // Write the decoded content to the file
        if (write(fileDescriptor, decodedContent, decodedLength) < 0) {
            perror("Error writing to file");
            exit(EXIT_FAILURE);
        }
    }

    // Close the file descriptor after the file is downloaded
    if (close(fileDescriptor) < 0) {
        perror("Error closing file");
        exit(EXIT_FAILURE);
    }

    free(directory);
    free(localFilePathFull);

    printf("File downloaded successfully.\n");
}

	


int createSocketAndConnect(const char *line) {
 char targetHost[MAX_HOST_SIZE];
 struct hostent *targetServer;
 struct sockaddr_in serverAddress;
 int socketFD;
 int targetPort = atoi(PORT);
 char buffer[BUFFER_SIZE];
 char *hostPart = strtok(buffer, " "); 
 socketFD = socket(AF_INET, SOCK_STREAM, 0);
 targetServer = gethostbyname(hostPart);

 strncpy(buffer, line, sizeof(buffer) - 1);
 buffer[sizeof(buffer) - 1] = '\0';

 if (!hostPart) {
 perror("Error: Invalid line format, host missing");
 return -1;
 }

 if (socketFD < 0) {
 perror("Error: Socket creation failed");
 return -1;
 }

 if (!targetServer) {
 perror("Error: No such host");
 close(socketFD);
 return -1;
 }

 memset((char *)&serverAddress, 0, sizeof(serverAddress));
 serverAddress.sin_family = AF_INET;
 memcpy((char *)&serverAddress.sin_addr.s_addr, (char *)targetServer->h_addr, targetServer->h_length);
 serverAddress.sin_port = htons(targetPort);

 // Connecting to the server
 if (connect(socketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
 perror("Error: Connection failed");
 close(socketFD);
 return -1;
 }

 return socketFD;
}

int countLinesInFile(const char *filePath) {
 FILE *file = fopen(filePath, "r");
 if (!file) {
 perror("Error opening file for line count");
 return -1;
 }

 int lineCount = 0;
 int currentCharacter;

 // Loop through each character in the file
 while ((currentCharacter = fgetc(file)) != EOF) {
 // Check for newline character
 if (currentCharacter == '\n') {
 lineCount++;
 }
 }

 // Close the file
 fclose(file);

 // Check for errors during file reading
 if (ferror(file)) {
 perror("Error reading file");
 return -1;
 }

 // Include the last line if not ending with a newline
 if (lineCount > 0 && currentCharacter != '\n') {
 lineCount++;
 }

 return lineCount;
}

void downloadFilesFromList(char *filePath) {
 int lineCount = countLinesInFile(filePath);
 char buffer[BUFFER_SIZE];

 if (lineCount <= 0) {
 perror("Error: Empty or invalid file");
 return;
 }

 struct pollfd pollFileDescriptors[lineCount];
 int fileDescriptors[BUFFER_SIZE];
 int fileDescriptor = open(filePath, O_RDONLY);

 if (fileDescriptor < 0) {
 perror("Error opening file");
 return;
 }

 FILE *file = fopen(filePath, "r");
 char line[BUFFER_SIZE];
 int i = 0;

 while (fgets(line, sizeof(line), file)) {
 int socketFD = createSocketAndConnect(line);

 if (socketFD < 0) {
 fprintf(stderr, "Error creating socket for line: %s\n", line);
 continue;
 }

 pollFileDescriptors[i].fd = socketFD;
 pollFileDescriptors[i].events = POLLIN;

 char *remotePath = strstr(line, " ") + 1;

 if (remotePath[strlen(remotePath) - 1] == '\n') {
 remotePath[strlen(remotePath) - 1] = '\0';
 } else {
 remotePath[strlen(remotePath)] = '\0';
 }

 printf("Sending GET request for: %s\n", remotePath);
 snprintf(buffer, BUFFER_SIZE, "GET %s\r\n\r\n", remotePath);

 if (write(socketFD, buffer, strlen(buffer)) < 0) {
 perror("Error writing to socket");
 continue;
 }

 char *directory = strdup(remotePath);

 char *lastSlash = strrchr(directory, '/');
 if (lastSlash) {
 *lastSlash = '\0';

 if (mkdir(directory, 0777) < 0 && errno != EEXIST) {
 perror("Error creating directory");
 continue;
 }
 }

 fileDescriptors[i] = open(remotePath, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

 if (fileDescriptors[i] < 0) {
 perror("Error creating file");
 continue;
 }

 free(directory);
 i++;
 }

 fclose(file);

 while (poll(pollFileDescriptors, lineCount, 1000) > 0) {
 for (int i = 0; i < lineCount; i++) {
 if (pollFileDescriptors[i].revents & POLLIN) {
 int numBytes = recv(pollFileDescriptors[i].fd, buffer, BUFFER_SIZE, 0);

 if (numBytes > 0) {
 char *decodedContent;
 size_t decodedLength = numBytes;

 if (base64_decoded((char *)buffer, &decodedContent, &decodedLength) != 0) {
 perror("Error decoding the content of the file");
 continue;
 }

 if (write(fileDescriptors[i], decodedContent, decodedLength) < 0) {
 perror("Error writing to file");
 continue;
 }
 } else if (numBytes == 0) {
 close(pollFileDescriptors[i].fd);
 pollFileDescriptors[i].fd = -1;
 } else perror("Error receiving data from socket");
 }
 }
 }

 for (int i = 0; i < lineCount; i++) {
 if (pollFileDescriptors[i].fd >= 0) 
 close(pollFileDescriptors[i].fd);
 close(fileDescriptors[i]);
 }
}

void sendFileUsingPOST(char *localFilePath, char *remotePath, int socketFD) {
    char buffer[BUFFER_SIZE];
    int bytesRead, writeResult;
    int localFileDescriptor = open(localFilePath, O_RDONLY);
    if (localFileDescriptor < 0) {
        perror("Error: Unable to open local file");
        return;
    }

    // Construct the POST request line
    snprintf(buffer, BUFFER_SIZE, "POST %s HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\n", remotePath);
    writeResult = write(socketFD, buffer, strlen(buffer));
    if (writeResult < 0) {
        perror("Error: Failed to send POST request header to the server");
        close(localFileDescriptor);
        return;
    }

    // Read file content, encode it, and send
    char fileBuffer[BUFFER_SIZE];
    while ((bytesRead = read(localFileDescriptor, fileBuffer, sizeof(fileBuffer))) > 0) {
        char *encodedContent = NULL;
        if (base64_encode(fileBuffer, &encodedContent, bytesRead) != 0) {
            perror("Error encoding file content");
            close(localFileDescriptor);
            return;
        }

        // Write encoded content to the socket
        writeResult = write(socketFD, encodedContent, strlen(encodedContent));
        if (writeResult < 0) {
            perror("Error sending encoded content to server");
            free(encodedContent);
            close(localFileDescriptor);
            return;
        }

        // Free the allocated memory for encoded content after sending
        free(encodedContent);
    }

    // Check for read errors
    if (bytesRead < 0) {
        perror("Error reading from file");
        close(localFileDescriptor);
        return;
    }

    // Sending the end of the request
    snprintf(buffer, BUFFER_SIZE, "\r\n");
    writeResult = write(socketFD, buffer, strlen(buffer));
    if (writeResult < 0) {
        perror("Error: Failed to send end of request to the server");
    }

    close(localFileDescriptor);
    printf("File %s sent successfully using POST to %s\n", localFilePath, remotePath);
}
int main(int argc, char *argv[]) {

 if (argc < 4) {
 fprintf(stderr, "Usage: %s <hostname> <operation:GET/POST> <remote_path> [<local_path_for_POST>]\n", argv[0]);
 exit(EXIT_FAILURE);
 }

 struct addrinfo addressInfoHints, *serverInfo, *pointer;
 memset(&addressInfoHints, 0, sizeof addressInfoHints);
 addressInfoHints.ai_family = AF_UNSPEC;
 addressInfoHints.ai_socktype = SOCK_STREAM;

 int returnVal;
 if ((returnVal = getaddrinfo(argv[1], PORT, &addressInfoHints, &serverInfo)) != 0) {
 fprintf(stderr, "Error in getaddrinfo: %s\n", gai_strerror(returnVal));
 return 1;
 }

 int socketFD; 
 // loop through all the results and connect to the first we can
 for(pointer = serverInfo; pointer != NULL; pointer = pointer->ai_next) {
 if ((socketFD = socket(pointer->ai_family, pointer->ai_socktype,
 pointer->ai_protocol)) == -1) {
 perror("Error creating socket in client");
 continue;
 }

 if (connect(socketFD, pointer->ai_addr, pointer->ai_addrlen) == -1) {
 perror("Error establishing connection in client");
 close(socketFD);
 continue;
 }

 break;
 }

 if (pointer == NULL) {
 fprintf(stderr, "Error: Failed to establish connection in client\n");
 return 2;
 }

 char serverAddress[INET6_ADDRSTRLEN];
 inet_ntop(pointer->ai_family, getIPAddressFromSockAddr((struct sockaddr *)pointer->ai_addr), serverAddress , sizeof (serverAddress));
 printf("Client: Connecting to server at %s\n", serverAddress);
 freeaddrinfo(serverInfo); 

 char* operationType = argv[2];
 char* remoteFilePath = argv[3];
 char* localFilePath = (argc == 5) ? argv[4] : NULL;
 if (strcmp(operationType, "GET") == 0) {
 downloadFileFromServer(remoteFilePath, socketFD);
 if (endsWithString(remoteFilePath, ".list")) {
 downloadFilesFromList(remoteFilePath);
 }
 }
 else if (strcmp(operationType, "POST") == 0) {
 sendFileUsingPOST(localFilePath, remoteFilePath, socketFD);
 } 
 else {
 printf("Error: Invalid operation\n");
 }
 
 close(socketFD);

 return 0;
}
