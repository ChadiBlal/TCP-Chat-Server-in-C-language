#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define PORT 8080
#define BACKLOG 10
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 2
#define AES_BLOCK_SIZE 16 // AES block size in bytes 
#define AES_KEY_SIZE 32 // AES-256 key size in bytes

int client_sockets[MAX_CLIENTS] = {0};

unsigned char aes_key[AES_KEY_SIZE]; // AES-256 Key (32 Bytes)

void error_handling(const char *msg);
int create_socket();
void bind_socket(int socketfd,struct sockaddr_in address);
void listen_socket(int socketfd);
int connect_to_client(int socketfd,struct sockaddr_in *client_addr,socklen_t *client_lent);
char* aes_encrypt(const unsigned char *key, const char *msg);
char* aes_decrypt(const unsigned char *key, const char *hex_input);
void load_aes_key();




int main() {

    // Load AES key from file
    load_aes_key();

    // Set up signal handling for graceful shutdown
    signal(SIGPIPE, SIG_IGN); // Ignore broken pipe signals

    
    fd_set readfds;
    int max_fd;
    int socketfd = create_socket();

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);
    address.sin_addr.s_addr = INADDR_ANY;

    bind_socket(socketfd, address);
    listen_socket(socketfd);

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(socketfd, &readfds);
        max_fd = socketfd;

        // Add all active clients to the set
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (client_sockets[i] > 0) {
                FD_SET(client_sockets[i], &readfds);
                if (client_sockets[i] > max_fd) {
                    max_fd = client_sockets[i];
                }
            }
        }

        int activity = select(max_fd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0 && errno != EINTR) {
            error_handling("select error");
        }

        // New connection handling
        if (FD_ISSET(socketfd, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_socket = accept(socketfd, (struct sockaddr*)&client_addr, &client_len);
            
            if (client_socket < 0) {
                error_handling("accept failed");
                continue;
            }

            printf("New connection: %s:%d\n", inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port));

            
            // Add new socket to array
            int added = 0;
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = client_socket;
                    added = 1;
                    break;
                }
            }
            
            if (!added) {
                printf("Max clients reached. Rejecting connection.\n");
                close(client_socket);
            }
        }

        // Check all clients for data
        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = client_sockets[i];
            if (sd > 0 && FD_ISSET(sd, &readfds)) {
                char buffer[BUFFER_SIZE];
                memset(buffer, 0, BUFFER_SIZE);

                uint32_t msg_len_net;
                int n = read(sd, &msg_len_net, sizeof(msg_len_net));
                if (n == 0) {
                    printf("Client disconnected\n");
                    close(sd);
                    client_sockets[i] = 0;
                    continue;
                }
                if (n != sizeof(msg_len_net)) {
                    error_handling("read length failed");
                }
                uint32_t msg_len = ntohl(msg_len_net);
                if (msg_len >= BUFFER_SIZE) {
                    error_handling("message too large");
                }
                int received = 0;
                while (received < (int)msg_len) {
                    int r = read(sd, buffer + received, msg_len - received);
                    if (r <= 0) {
                        printf("Client disconnected\n");
                        close(sd);
                        client_sockets[i] = 0;
                        break;
                    }
                    received += r;
                }
                buffer[msg_len] = '\0';

                // Decrypt the message
                char *decrypted_msg = aes_decrypt(aes_key, buffer);
                printf("Client %d: %s\n", sd, decrypted_msg);

                // Broadcast encrypted message to all other clients
                char *encrypted_msg = aes_encrypt(aes_key, decrypted_msg);
                for (int j = 0; j < MAX_CLIENTS; j++) {
                    if (client_sockets[j] > 0 && client_sockets[j] != sd) {
                        uint32_t out_len = htonl(strlen(encrypted_msg));
                        if (write(client_sockets[j], &out_len, sizeof(out_len)) != sizeof(out_len)) {
                            perror("broadcast length failed");
                            close(client_sockets[j]);
                            client_sockets[j] = 0;
                            continue;
                        }
                        if (write(client_sockets[j], encrypted_msg, strlen(encrypted_msg)) != (ssize_t)strlen(encrypted_msg)) {
                            perror("broadcast message failed");
                            close(client_sockets[j]);
                            client_sockets[j] = 0;
                        }
                    }
                }
                free(decrypted_msg);
                free(encrypted_msg);
            }
        }
    }

    close(socketfd);
    return 0;
}


void error_handling(const char *msg){
    perror(msg);
    exit(EXIT_FAILURE);
}

int create_socket(){
    int socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketfd < 0)
            error_handling("The socket creation has failed ");
    return socketfd;
}

void bind_socket(int socketfd,struct sockaddr_in address){ 
    if(bind(socketfd,(struct sockaddr*)&address,sizeof(address))<0)
    error_handling("Bind Failed ");
}

void listen_socket(int socketfd){
    if(listen(socketfd,BACKLOG) <0)
    error_handling("Listen failed ");
    printf("The server now is Listening in port %d\n",PORT); 
}

int connect_to_client(int socketfd,struct sockaddr_in *client_addr,socklen_t *client_lent){
    int client_socket = accept(socketfd,(struct sockaddr*)client_addr,client_lent);
    if(client_socket < 0)
    error_handling("connection falied ");
    return client_socket;
}

// Encrypt and decrypt functions

char* aes_encrypt(const unsigned char *key, const char *msg) {
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE); // Generate random IV
    
    //key expansion process (Creating 15 keys to use in rounds)
    AES_KEY enc_key;
    AES_set_encrypt_key(key, 256, &enc_key);
    
    // Pad message to 16-byte boundary
    int msg_len = strlen(msg) + 1;
    int padded_len = ((msg_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    unsigned char *padded_msg = calloc(padded_len, 1);
    strcpy((char*)padded_msg, msg);
    
    // Encrypt (IV + ciphertext)
    unsigned char *ciphertext = calloc(AES_BLOCK_SIZE + padded_len, 1);
    memcpy(ciphertext, iv, AES_BLOCK_SIZE); // Prepend IV
    AES_cbc_encrypt(padded_msg, ciphertext + AES_BLOCK_SIZE, padded_len, &enc_key, iv, AES_ENCRYPT);
    //XORing the plain text with the IV then encrypt our plaintext XOR IV
    
    // Return as hex string (simpler than base64)
    char *hex_output = calloc(2*(AES_BLOCK_SIZE + padded_len) + 1, 1);
    for(int i = 0; i < AES_BLOCK_SIZE + padded_len; i++){
        sprintf(hex_output + 2*i, "%02x", ciphertext[i]);
        }
    
    free(padded_msg);
    free(ciphertext);
    return hex_output;
}

char* aes_decrypt(const unsigned char *key, const char *hex_input) {
    int hex_len = strlen(hex_input);
    int cipher_len = hex_len / 2;
    unsigned char *ciphertext = calloc(cipher_len, 1);
    
    // Convert hex to binary
    for(int i = 0; i < cipher_len; i++)
        sscanf(hex_input + 2*i, "%02hhx", &ciphertext[i]);
    
    // Extract IV (first 16 bytes)
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, ciphertext, AES_BLOCK_SIZE);
    
    AES_KEY dec_key;
    AES_set_decrypt_key(key, 256, &dec_key);
    
    // Decrypt
    unsigned char *decrypted = calloc(cipher_len - AES_BLOCK_SIZE + 1, 1);// Ensure null-termination
    AES_cbc_encrypt(ciphertext + AES_BLOCK_SIZE, decrypted, 
                   cipher_len - AES_BLOCK_SIZE, &dec_key, iv, AES_DECRYPT);
    decrypted[cipher_len - AES_BLOCK_SIZE] = '\0'; // Ensure null-termination

    free(ciphertext);
    return (char*)decrypted;

}

void load_aes_key(){
    // Open the AES key file
    FILE *f = fopen("aes_key_Kali.txt","rb");
    if (!f){
        fprintf(stderr,"Error opening key file:%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Read the AES key from the file 
    size_t bytes_read = fread(aes_key, 1, AES_KEY_SIZE, f);
    if(bytes_read != AES_KEY_SIZE){
        fprintf(stderr,"Expected %d bytes, got %zu\n", AES_KEY_SIZE, bytes_read);
        exit(EXIT_FAILURE);
    }

    unsigned char extra;
    // Check if there are any extra bytes
    size_t extra_bytes = fread(&extra, 1, 1, f);
    if(extra_bytes > 0) {
        fprintf(stderr, "Warning: Extra bytes found in key file: %zu\n", extra_bytes);
    }

    fclose(f);
}