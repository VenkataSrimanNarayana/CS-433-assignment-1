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
#include "flow.h"
#include "flow_table.h"

#define BUFFER_SIZE 65536

// Add a new TCP Flow to the TCP Flow Table
void packet_handler(FlowTable *table, unsigned char *packet, int packet_length)
{
    struct ethhdr *ethernet_header = (struct ethhdr *)packet;
    packet_length -= sizeof(struct ethhdr);
    if (ethernet_header->h_proto != ntohs(ETH_P_IP))
        return;

    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    packet_length -= (ip_header->ihl * 4);

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

    // Get the TCP payload
    unsigned char *payload = packet + sizeof(struct ethhdr) + (ip_header->ihl * 4) + (tcp_header->doff * 4);
    int payload_length = packet_length - (tcp_header->doff * 4);

    // Search for the TCP Flow in the TCP Flow Table
    Flow *flow = search_flow_in_table(table, source_ip, destination_ip, source_port, destination_port);
    // If the TCP Flow is not present in the TCP Flow Table, add it to the TCP Flow Table
    if (flow == NULL)
    {
        // Assuming the initial packet is from the client
        flow = add_flow_to_table(table, source_ip, destination_ip, source_port, destination_port);
    }
    // Add the packet data to the TCP Flow
    add_packet_data_to_flow(flow, payload, payload_length, checksum);
}

// Print the TCP Flow Table and its statistics
void print_stats(FlowTable *table)
{
    // print the TCP Flow Table
    print_flow_table(table);
    // print the statistics of the TCP Flow Table
    printf("Statistics:\n");
    printf("  Total number of flows: %d\n", table->size);
    // doing a reverse dns lookup for 5 distinct IP address
    printf("  5 Distinct Server IP addresses:\n");
    int count = 0;
    int addr[5];
    for (int i = 0; i < table->size; i++)
    {
        if (count == 5)
            break;
        // search for the IP address in the addr array
        int found = 0;
        for (int j = 0; j < count; j++)
        {
            if (addr[j] == table->flows[i].server)
            {
                found = 1;
                break;
            }
        }
        if (found == 1)
            continue;
        struct hostent *host = gethostbyaddr(&table->flows[i].server, sizeof(table->flows[i].server), AF_INET);
        if (host != NULL)
        {
            printf("    %s : %s\n", inet_ntoa(*(struct in_addr *)&table->flows[i].server), host->h_name);
            addr[count] = table->flows[i].server;
            count++;
        }
    }
}

// Global TCP Flow Table
FlowTable *table;

// Signal handler for ctrl+c
void signal_handler(int signal)
{
    if (signal == SIGINT)
    {
        print_stats(table);
        // Free the memory allocated for the TCP Flow Table
        free_flow_table(table);
        exit(0);
    }
}

int main()
{
    int sock;
    unsigned char buffer[BUFFER_SIZE];
    // setting signal for ctrl+c
    signal(SIGINT, signal_handler);
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
    }
    close(sock);
    return 0;
}
