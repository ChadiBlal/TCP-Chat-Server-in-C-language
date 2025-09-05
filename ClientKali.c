#include <stdio.h>
#include <string.h>
#include <stdlib.h>        
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <errno.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <signal.h>

#define MAX_CLIENTS 2
#define AES_BLOCK_SIZE 16 // AES block size in bytes 
#define AES_KEY_SIZE 32 // AES-256 key size in bytes
#define PORT 8080
#define BUFFER_SIZE 1024

unsigned char aes_key[AES_KEY_SIZE]; // AES-256 Key (32 Bytes)

void communicate_with_server(int client_socket);
int create_socket();
void connect_to_server(int client_socket,const char *ip_server);
void error_handling(const char *msg);
char* aes_encrypt(const unsigned char *key, const char *msg);
char* aes_decrypt(const unsigned char *key, const char *hex_input);
void load_aes_key();


int main(){
    // Load AES key from file
    load_aes_key();

    // Set up signal handling for graceful shutdown
    signal(SIGPIPE, SIG_IGN); // Ignore broken pipe signals
    int client_socket = create_socket();
    connect_to_server(client_socket,"192.168.79.128");
    communicate_with_server(client_socket);
    close(client_socket);
    return 0;
}

void error_handling(const char *msg){
    perror(msg);
    exit(1);
}

int create_socket(){
    int client_socket = socket(AF_INET, SOCK_STREAM,0);
    if(client_socket < 0)
    error_handling(" socket creation failed ");
    return client_socket;
}

void connect_to_server(int client_socket,const char *ip_server){
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if(inet_pton(AF_INET,ip_server,&server_addr.sin_addr) <= 0)
    error_handling("Invalid address");

    if(connect(client_socket,(struct sockaddr*)&server_addr,sizeof(server_addr))< 0)
    error_handling("Connectio failed");

    printf("The client is connected to the server %s:%d\n",ip_server,PORT);
}

void communicate_with_server(int client_socket) {
    char msg[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(client_socket, &readfds);
        FD_SET(STDIN_FILENO, &readfds); // Monitor stdin (user input)

        // Wait for either server data or user input
        int activity = select(client_socket + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0) error_handling("select failed");

        // Case 1: Server sent a message
        if (FD_ISSET(client_socket, &readfds)) {
            memset(buffer, 0, BUFFER_SIZE);
            uint32_t msg_len_net;
        int n = read(client_socket, &msg_len_net, sizeof(msg_len_net));
        if (n == 0) {
           printf("Server disconnected!\n");
           break;
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
        int r = read(client_socket, buffer + received, msg_len - received);
        if (r <= 0) {
        printf("Server disconnected!\n");
        break;
        }
        received += r;
        }
        
buffer[msg_len] = '\0';
char *decrypted_msg = aes_decrypt(aes_key, buffer);
printf("📩 New message: %s\n> ", decrypted_msg);
free(decrypted_msg);
            
        }

        // Case 2: User typed a message
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            fgets(msg, BUFFER_SIZE, stdin);
            msg[strcspn(msg, "\n")] = '\0';
            
            // encrypt the message before sending
            char *encrypted_msg = aes_encrypt(aes_key, msg);
            uint32_t msg_len = htonl(strlen(encrypted_msg));
            if (write(client_socket, &msg_len, sizeof(msg_len)) != sizeof(msg_len))
                error_handling("write length failed");
            if (write(client_socket, encrypted_msg, strlen(encrypted_msg)) != (ssize_t)strlen(encrypted_msg))
                error_handling("write message failed");
            
            if (strcmp(msg, "exit") == 0) break;
        }
    }
}

//encrypt and decrypt functions

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
    unsigned char *decrypted = calloc(cipher_len - AES_BLOCK_SIZE + 1, 1);
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