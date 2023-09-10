#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <memory.h>
#include <signal.h>
#include <netdb.h>
#include <regex.h>
#include <time.h>
#include <string.h>

#define BUFFER_SIZE 65536
#define ARRAY_SIZE 10000

/* Defining helper Data structures and functions */
// Define Packet structure
typedef struct
{
    unsigned char *data;
    int size;
    uint16_t checksum;
} Packet;

// Define a TCP Flow
typedef struct
{
    uint32_t client, server;
    uint16_t client_port, server_port;
    int size;
    int capacity;
    Packet *packets;
    uint32_t pid;
} Flow;

// Define a TCP Flow Table
typedef struct
{
    Flow *flows;
    int size;
    int capacity;
} FlowTable;

// Global TCP Flow Table
FlowTable *table;

// get current ip address.
char *getIPAddress()
{
    FILE *fp;
    char buffer[256];
    char *token;
    char *ip = NULL;

    // Open the 'ifconfig' command and read its output
    fp = popen("/sbin/ifconfig", "r");
    if (fp == NULL)
    {
        perror("Failed to run ifconfig");
        exit(1);
    }

    // Search for the first occurrence of "inet" (IPv4) in the output
    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        if ((token = strstr(buffer, "inet ")) != NULL)
        {
            ip = strtok(token + 5, " "); // Extract the IP address
            break;
        }
    }

    // Close the command output
    pclose(fp);

    // Return the IP address as a dynamically allocated string
    if (ip != NULL)
    {
        return strdup(ip);
    }
    else
    {
        return NULL;
    }
}

// helperFunctions
// fetch pid using client portNumber
uint32_t fetchPID(uint16_t portNumber)
{

    char buffer[128]; // Buffer to store each line of output
    char command[128];
    FILE *fp;

    snprintf(command, sizeof(command), "sudo netstat -p | grep %d | grep -oP '\\d+' | tail -n 1", portNumber);
    // Run the "netstat" command and capture its output
    fp = popen(command, "r");
    if (fp == NULL)
    {
        perror("popen");
        exit(EXIT_FAILURE);
    }

    uint32_t pid;
    // Read and print each line of output
    if (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        pid = atoi(strdup(buffer));
    }
    else
    {
        return 0;
    }

    // Close the file pointer
    pclose(fp);
    return pid;
}

// Add a new packet data to a TCP Flow
void add_packet_data_to_flow(Flow *flow, unsigned char *data, int size, uint16_t checksum, uint32_t pid)
{
    if (flow->size == flow->capacity)
    {
        flow->capacity *= 2;
        flow->packets = (Packet *)realloc(flow->packets, flow->capacity * sizeof(Packet));
    }
    flow->packets[flow->size].data = (unsigned char *)malloc(size * sizeof(unsigned char));
    memcpy(flow->packets[flow->size].data, data, size);
    flow->packets[flow->size].size = size;
    flow->pid = pid;
    flow->packets[flow->size].checksum = checksum;
    flow->size++;
}

// Initialize a TCP Flow Table
FlowTable *init_flow_table()
{
    FlowTable *table = (FlowTable *)malloc(sizeof(FlowTable));
    table->size = 0;
    table->capacity = 2;
    table->flows = (Flow *)malloc(table->capacity * sizeof(Flow));
    return table;
}

// Add a new TCP Flow to the TCP Flow Table
Flow *add_flow_to_table(FlowTable *table, uint32_t client, uint32_t server, uint16_t client_port, uint16_t server_port)
{
    if (table->size == table->capacity)
    {
        table->capacity *= 2;
        table->flows = (Flow *)realloc(table->flows, table->capacity * sizeof(Flow));
    }
    table->flows[table->size].client = client;
    table->flows[table->size].server = server;
    table->flows[table->size].client_port = client_port;
    table->flows[table->size].server_port = server_port;
    table->flows[table->size].size = 0;
    table->flows[table->size].capacity = 2;
    table->flows[table->size].packets = (Packet *)malloc(table->flows[table->size].capacity * sizeof(Packet));
    table->size++;
    return &table->flows[table->size - 1];
}

// Search for a TCP Flow in the TCP Flow Table
Flow *search_flow_in_table(FlowTable *table, uint32_t client, uint32_t server, uint16_t client_port, uint16_t server_port)
{
    for (int i = 0; i < table->size; i++)
    {
        if (table->flows[i].client == client && table->flows[i].server == server && table->flows[i].client_port == client_port && table->flows[i].server_port == server_port)
            return &table->flows[i];
        if (table->flows[i].client == server && table->flows[i].server == client && table->flows[i].client_port == server_port && table->flows[i].server_port == client_port)
            return &table->flows[i];
    }
    return NULL;
}

// Add a new TCP Flow to the TCP Flow Table
void packet_handler(FlowTable *table, unsigned char *packet, int packet_length)
{
    struct ethhdr *ethernet_header = (struct ethhdr *)packet;
    packet_length -= sizeof(struct ethhdr);
    if (ethernet_header->h_proto != ntohs(ETH_P_IP))
        return;

    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    packet_length -= sizeof(struct iphdr);

    // Allowing only TCP packets
    if (ip_header->protocol != IPPROTO_TCP)
        return;

    // Get the tcp flow details(i.e, source and destination IP)
    uint32_t source_ip = ip_header->saddr;
    uint32_t destination_ip = ip_header->daddr;

    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header->ihl * 4);
    // Get the port numbers in the TCP header
    uint16_t source_port = ntohs(tcp_header->source);
    uint16_t destination_port = ntohs(tcp_header->dest);
    // Get the checksum in the TCP header
    uint16_t checksum = ntohs(tcp_header->check);

    // Get the process id corresponding to the source port
    // check if the source ip is same as the current ip
    uint32_t processid;
    if (source_ip == inet_addr(getIPAddress()))
    {
        processid = fetchPID(source_port);
    }
    else
    {
        processid = fetchPID(destination_port);
    }

    // printf("%s", "available ports: ");
    // printf("%d \n", source_port);
    // printf("%d \n", destination_port);

    // Get the TCP payload including the TCP header
    unsigned char *payload = packet + sizeof(struct ethhdr) + (ip_header->ihl * 4);
    int payload_length = packet_length;

    // Search for the TCP Flow in the TCP Flow Table
    Flow *flow = search_flow_in_table(table, source_ip, destination_ip, source_port, destination_port);
    // If the TCP Flow is not present in the TCP Flow Table, add it to the TCP Flow Table
    if (flow == NULL)
    {
        flow = add_flow_to_table(table, source_ip, destination_ip, source_port, destination_port);
    }
    // Add the packet data to the TCP Flow
    add_packet_data_to_flow(flow, payload, payload_length, checksum, processid);
}

// printing the TCP Flow Table
void print_flow(FlowTable *table)
{
    int flow_number = 1;
    // Iterate through all the TCP Flows in the TCP Flow Table
    for (int i = 0; i < table->size; i++)
    {
        printf("Flow - %d\n", flow_number++);
        printf("  Client IP: %s\n", inet_ntoa(*(struct in_addr *)&table->flows[i].client));
        printf("  Server IP: %s\n", inet_ntoa(*(struct in_addr *)&table->flows[i].server));
        printf("  Client Port: %d\n", table->flows[i].client_port);
        printf("  Server Port: %d\n", table->flows[i].server_port);
    }
}

// Search for the given port number in the TCP Flow Table
Flow *search_flow_by_client_port(FlowTable *table, uint16_t port, char *ip)
{

    for (int i = 0; i < table->size; i++)
    {
        if (table->flows[i].client == inet_addr(ip))
            if (table->flows[i].client_port == port)
                return &table->flows[i];
    }
    return NULL;
}

int main()
{
    int sock;
    unsigned char buffer[BUFFER_SIZE];

    // Creating a Stream sockets
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    // Error handling code
    if (sock < 0)
    {
        perror("Socket creation failed");
        return 1;
    }

    // Initialize the TCP Flow Table
    table = init_flow_table();

    // setting timer
    int durationInSeconds = 30;
    time_t startTime = time(NULL);

    // printf("%s", "available ports");
    // capturing packets
    // print_flow_table(table);

    while (1)
    {
        int packet_length = recvfrom(sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (packet_length < 0)
        {
            perror("Packet receive failed");
            close(sock);
            return 1;
        }

        packet_handler(table, buffer, packet_length);
        time_t endTime = time(NULL);
        int elapsedSeconds = difftime(endTime, startTime);
        // printf("\n%d\n", elapsedSeconds);
        if (elapsedSeconds >= 30)
        {
            break;
        }
    }

    close(sock);

    // printing the TCP Flow Table
    print_flow(table);

    // get the IP address of the device
    char *ip = getIPAddress();
    // printf("IP Address: %s\n", ip);

    // Prompt the user to enter a port number to look up the PID until the click Ctrl+C
    while (1)
    {
        int port_str;
        // Prompt the user to enter a port number to look up the PID
        printf("Enter a port number to look up the corresponding PID: ");
        scanf("%d", &port_str);
        // Get the flow corresponding to the given port number
        Flow *flow = search_flow_by_client_port(table, port_str, ip);
        if (flow == NULL)
        {
            printf("No flow found with the given port number\n");
        }
        else
        {
            printf("PID: %d\n", flow->pid);
        }
    }

    free(ip); // Free the dynamically allocated memory for IP address
    return 0;
}