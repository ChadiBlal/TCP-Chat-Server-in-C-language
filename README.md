[TCP-Chat-Server-README.md](https://github.com/user-attachments/files/31078944/TCP-Chat-Server-README.md)
# TCP Chat Server in C

A Linux-based TCP chat application written in C using socket programming. The project includes a multi-client server and a client program that exchange encrypted messages over a TCP connection.

## Features

- TCP client–server communication using POSIX sockets.

- Support for up to two simultaneous clients.

- Message broadcasting between connected clients.

- Multiplexed I/O using `select()`.

- AES-256-CBC encryption with a randomly generated IV for each message.

- Length-prefixed message framing to handle messages reliably over TCP.

- Graceful handling of client disconnections and server shutdown signals.

## Technologies

- C

- Linux/Unix socket programming

- TCP/IP

- OpenSSL Crypto Library

- `select()` for I/O multiplexing

## Project Structure

```
.
├── Server.c          # TCP chat server
├── ClientKali.c      # TCP chat client
└── README.md
```

## Requirements

A Linux or Kali Linux environment is recommended. Install GCC and the OpenSSL development library:

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

## Configuration

The client currently contains the server IP address directly in `ClientKali.c`:

```
connect_to_server(client_socket, "SERVER_IP_ADDRESS");
```

Replace `SERVER_IP_ADDRESS` with the address of the machine running the server. The application uses port `8080` by default.

Both the server and the client require the same 32-byte AES key file named `aes_key_Kali.txt` in their working directory. Generate a local development key with:

```bash
openssl rand 32 > aes_key_Kali.txt
```

Do not commit this key file to a public repository.

## Compilation

Compile the server and client with OpenSSL:

```bash
gcc Server.c -o Server -lcrypto
gcc ClientKali.c -o ClientKali -lcrypto
```

## Usage

Start the server first:

```bash
./Server
```

Then start one or two clients from separate terminals or machines:

```bash
./ClientKali
```

Type a message in one client to broadcast it to the other connected client. Type `exit` to close the client connection.

## Learning Objectives

This project was developed to practice socket creation, TCP communication, client management, I/O multiplexing, message framing, and the integration of cryptographic operations into a network application.

## Security Note

This project is an educational prototype and is not intended for production use. Although it uses AES-256-CBC encryption, the shared key is stored as a local file and the current implementation does not provide modern authenticated encryption or user authentication. Use it only in a controlled laboratory environment.

## Author

**Chadi Blal**

- GitHub: [@ChadiBlal](https://github.com/ChadiBlal)

- LinkedIn: [www.linkedin.com/in/chadi-blal-01817236a](http://www.linkedin.com/in/chadi-blal-01817236a)



