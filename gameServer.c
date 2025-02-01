#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#define BUFFER_SIZE 1024
#define DEBUG 0

// Debugging macros
#if DEBUG
#define DEBUG_PRINT(fmt, ...) \
        fprintf(stderr, "DEBUG: " fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) \
        do { } while (0)
#endif

// Structure to represent a message node in the queue
typedef struct MessageNode {
    char message[BUFFER_SIZE];
    struct MessageNode *next;
} MessageNode;

// Structure to represent a client
typedef struct {
    int fd;                 // Client socket descriptor
    int id;                 // Client ID (1 to MAX_CLIENTS)
    MessageNode *queue;     // Message queue head
    MessageNode *queue_tail; // Message queue tail
} Client;

// Global variables
int max_players, listen_fd, max_fd, target_num, client_count = 0, game_over = 0;
Client* clients;

// Function prototypes
int isInteger(const char *str);
int enqueue_message(Client *client, const char *message);
char *dequeue_message(Client *client);
void free_clients();
void free_message_queue(Client* client);
int broadcast_message(Client* clients, const char *message, fd_set* set_write, int max_fd, int current_client);
void cleanup_and_exit(int signum);
void accept_new_client(int *client_count, int* max_fd, fd_set* temp_set_read, fd_set* temp_set_write);
void handle_client_input(int i, fd_set *temp_set_read, fd_set *temp_set_write);
void send_message(int i, fd_set *temp_set_read, fd_set *temp_set_write);
void update_max_fd();

int main(int argc, char *argv[]) {
    // Validate command-line arguments
    if (argc != 4) {
        printf("Usage: ./server <port> <seed> <max-number-of-players>\n");
        exit(EXIT_FAILURE);
    }

    if (!isInteger(argv[1]) || !isInteger(argv[2]) || !isInteger(argv[3])) {
        printf("Usage: ./server <port> <seed> <max-number-of-players>\n");
        exit(EXIT_FAILURE);
    }

    // Register the SIGINT signal handler
    signal(SIGINT, cleanup_and_exit);

    // Parse command-line arguments
    int port = atoi(argv[1]);
    int seed = atoi(argv[2]);
    max_players = atoi(argv[3]);

    // Initialize random number generator
    srand(seed);
    target_num = (rand() % 100) + 1;

    // Server address structure
    struct sockaddr_in srv;

    // Create the socket
    if ((listen_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    srv.sin_addr.s_addr = htonl(INADDR_ANY);

    // Bind the socket to the server address
    if (bind(listen_fd, (struct sockaddr *) &srv, sizeof(srv)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    // Initialize variables for handling clients and file descriptors
    int activity;
    fd_set set_read, set_write, temp_set_read, temp_set_write;

    // Allocate memory for clients
    clients = (Client *) malloc(max_players * sizeof(Client));
    if (!clients) {
        perror("malloc");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }
    memset(clients, 0, max_players * sizeof(Client));

    // Initialize file descriptor sets
    FD_ZERO(&temp_set_read);
    FD_ZERO(&temp_set_write);
    FD_SET(listen_fd, &temp_set_read);
    max_fd = listen_fd;

    // Main server loop
    while (1) {
        set_read = temp_set_read;
        set_write = temp_set_write;

        // Manage the listen socket based on the number of connected clients
        if (client_count == max_players)
            FD_CLR(listen_fd, &set_read);
        else
            FD_SET(listen_fd, &set_read);

        // Wait for activity on any file descriptor
        activity = select(max_fd + 1, &set_read, &set_write, NULL, NULL);
        if (activity < 0) {
            perror("select");
            cleanup_and_exit(-1);
        }

        DEBUG_PRINT("%s\n", temp_set_read);

        // Handle new client connection
        if (FD_ISSET(listen_fd, &set_read)) {
            printf("Server is ready to read from welcome socket %d\n", listen_fd);
            accept_new_client(&client_count, &max_fd, &temp_set_read, &temp_set_write);
            activity--;
        }

        // Handle activity for existing clients
        for (int i = 0; i < max_players && activity > 0; i++) {
            if (clients[i].fd != 0) {
                if (FD_ISSET(clients[i].fd, &set_read)) {
                    // Check for readable data
                    printf("Server is ready to read from player %d on socket %d\n", clients[i].id, clients[i].fd);
                    handle_client_input(i, &temp_set_read, &temp_set_write);
                    activity--;
                }
                if (FD_ISSET(clients[i].fd, &set_write)) {
                    // Check for writable data
                    printf("Server is ready to write to player %d on socket %d\n", clients[i].id, clients[i].fd);
                    send_message(i, &temp_set_read, &temp_set_write);
                    activity--;
                }
            }
        }
        if (game_over && client_count == 0) {
            target_num = (rand() % 100) + 1;
            game_over = 0;
            max_fd = listen_fd;
        }
    }
}

// Function to check if a string is a valid integer
int isInteger(const char *str) {
    char *endptr;

    long value = strtol(str, &endptr, 10);

    // Check if the entire string was consumed
    if (*endptr != '\0') {
        return 0; // Not a valid integer
    }

    // Ensure the value is within the range of an integer
    if (value < INT_MIN || value > INT_MAX) {
        return 0; // Out of integer range
    }

    return 1; // Valid integer
}

// Function to enqueue a message for a client
int enqueue_message(Client *client, const char *message) {
    MessageNode *new_node = (MessageNode *)malloc(sizeof(MessageNode));
    if (!new_node) {
        perror("Failed to allocate memory for message");
        return -1;
    }
    strncpy(new_node->message, message, BUFFER_SIZE);
    new_node->next = NULL;

    if (!client->queue) {
        client->queue = new_node;
        client->queue_tail = new_node;
    } else {
        client->queue_tail->next = new_node;
        client->queue_tail = new_node;
    }

    return 0;
}

// Function to dequeue a message for a client
char *dequeue_message(Client *client) {
    if (!client->queue) {
        return NULL;
    }

    MessageNode *node = client->queue;
    char *message = strdup(node->message);
    client->queue = client->queue->next;
    if (!client->queue) {
        client->queue_tail = NULL;
    }
    free(node);
    return message;
}

// Function to free all clients and their message queues
void free_clients() {
    DEBUG_PRINT("max players; %d\n", max_players);
    for (int i = 0; i < max_players; i++) {
        DEBUG_PRINT("%d\n", clients[i].fd);
        if (clients[i].fd != 0) {
            close(clients[i].fd);
            free_message_queue(&clients[i]);
        }
    }
}

// Function to free a client's message queue
void free_message_queue(Client* client) {
    MessageNode* current = client->queue;
    MessageNode* next = current;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
    client->queue = client->queue_tail = NULL;
}

// Function to broadcast a message to all clients
int broadcast_message(Client* clients, const char *message, fd_set* set_write, int max_fd, int current_client) {
    for (int j = 0; j < max_players; j++) {
        if (clients[j].fd != 0) {
            // Case 1: Broadcast to all clients (including the current client)
            if (current_client == -1) {
                if (enqueue_message(&clients[j], message) < 0)
                    return -1;
                FD_SET(clients[j].fd, set_write);
            }
                // Case 2: Broadcast to all clients except the current client
            else if (j != current_client) {
                if (enqueue_message(&clients[j], message) < 0)
                    return -1;
                FD_SET(clients[j].fd, set_write);
            }
        }
    }

    return 0;
}

// Function to clean up resources and exit
void cleanup_and_exit(int signum) {
    free_clients();
    free(clients);
    if (listen_fd > 0)
        close(listen_fd);
    if (signum == -1)
        exit(EXIT_FAILURE);
    exit(EXIT_SUCCESS);
}

// Function to accept a new client connection
void accept_new_client(int *client_count, int* max_fd, fd_set* temp_set_read, fd_set* temp_set_write) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    if (*client_count < max_players) {
        int new_socket = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (new_socket < 0) {
            perror("accept");
            cleanup_and_exit(-1);
        }
        char buffer[BUFFER_SIZE];
        // Add the client to the active list
        for (int i = 0; i < max_players; i++) {
            if (clients[i].fd == 0) {
                clients[i].fd = new_socket;
                clients[i].id = i + 1;
                FD_SET(new_socket, temp_set_read);
                *max_fd = new_socket > *max_fd ? new_socket : *max_fd;
                (*client_count)++;
                sprintf(buffer, "Welcome to the game, your id is %d\n", clients[i].id);
                if (enqueue_message(&clients[i], buffer) < 0) {
                    cleanup_and_exit(-1);
                }
                FD_SET(clients[i].fd, temp_set_write);
                sprintf(buffer, "Player %d joined the game\n", clients[i].id);
                if (broadcast_message(clients, buffer, temp_set_write, *max_fd, i) < 0)
                    cleanup_and_exit(-1);
                break;
            }
        }
    }
}

void handle_client_input(int i, fd_set *temp_set_read, fd_set *temp_set_write) {
    char buffer[BUFFER_SIZE];
    char num_buffer[20];
    int bytes_read = read(clients[i].fd, num_buffer, sizeof(num_buffer));
    if (bytes_read <= 0) {
        // Client disconnected
        close(clients[i].fd);
        FD_CLR(clients[i].fd, temp_set_read);
        FD_CLR(clients[i].fd, temp_set_write);
        free_message_queue(&clients[i]);
        client_count--;
        sprintf(buffer, "Player %d disconnected\n", clients[i].id);
        if (broadcast_message(clients, buffer, temp_set_write, max_fd, i) < 0)
            cleanup_and_exit(-1);
        clients[i].id = 0;
        if (clients[i].fd == max_fd)
            update_max_fd();
        clients[i].fd = 0;
    } else {
        // Null-terminate the buffer
        num_buffer[bytes_read] = '\0';

        // Convert the string to an integer
        int num = atoi(num_buffer);

        sprintf(buffer, "Player %d guessed %d\n", clients[i].id, num);
        if (broadcast_message(clients, buffer, temp_set_write, max_fd, -1) < 0)
            cleanup_and_exit(-1);

        if (num < target_num)
            sprintf(buffer, "The guess %d is too low\n", num);
        else if (num > target_num)
            sprintf(buffer, "The guess %d is too high\n", num);
        else
            sprintf(buffer, "Player %d wins\n", clients[i].id);

        if (broadcast_message(clients, buffer, temp_set_write, max_fd, -1) < 0)
            cleanup_and_exit(-1);
        // Notify all clients of the correct number
        if (num == target_num) {
            game_over = 1;
            sprintf(buffer, "The correct guessing is %d\n", num);
            if (broadcast_message(clients, buffer, temp_set_write, max_fd, -1) < 0) {
                cleanup_and_exit(-1);
            }
        }
    }
}

void send_message(int i, fd_set *temp_set_read, fd_set *temp_set_write) {
    char *message = dequeue_message(&clients[i]);
    if (message) {
        write(clients[i].fd, message, strlen(message));
        free(message);
    }

    if (!clients[i].queue) {
        FD_CLR(clients[i].fd, temp_set_write);
        if (game_over) {
            close(clients[i].fd);
            client_count--;
            FD_CLR(clients[i].fd, temp_set_read);
            FD_CLR(clients[i].fd, temp_set_write);
            clients[i].id = 0;
            if (clients[i].fd == max_fd)
                update_max_fd();
            clients[i].fd = 0;
        }
    }
}

void update_max_fd() {
    max_fd = 0;
    for (int i = 0; i < max_players; i++) {
        if (clients[i].id > 0) {
            if (clients[i].fd > max_fd)
                max_fd = clients[i].fd;
        }
    }
}