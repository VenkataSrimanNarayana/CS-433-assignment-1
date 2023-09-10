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
#include <ctype.h>

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
        flow = add_flow_to_table(table, source_ip, destination_ip, source_port, destination_port);
    }
    // Add the packet data to the TCP Flow
    add_packet_data_to_flow(flow, payload, payload_length, checksum);
}

// find and print the packet data that contains a given string along with checksum
void find_and_print(FlowTable *table, char *str)
{
    // Iterate through all the TCP Flows in the TCP Flow Table
    for (int i = 0; i < table->size; i++)
    {
        // Iterate through all the packets in the TCP Flow
        for (int j = 0; j < table->flows[i].size; j++)
        {
            // If the packet data contains the given string, print the packet data
            if (strstr((char *)table->flows[i].packets[j].data, str) != NULL)
            {
                printf("    Packet Data: %s\n", table->flows[i].packets[j].data);
                printf("    Checksum: %d\n", table->flows[i].packets[j].checksum);
            }
        }
    }
}

/* There is a Flag in a TCP Packet. Identify the flag.
(Hint: Search for the keyword Flag) */
void one(FlowTable *table)
{
    // print the packet containing the string 'Flag: '
    find_and_print(table, "Flag: ");
}

/*My username is secret, Identify my secret*/
void two(FlowTable *table)
{
    // print the packet containing the string 'username=secret'
    find_and_print(table, "username=secret");
}
/* I have a TCP checksum “0xf436”. I have instructions in my path. */
void three(FlowTable *table)
{
    Flow *flow;
    // search for a packet with checksum 0xf436
    for (int i = 0; i < table->size; i++)
    {
        for (int j = 0; j < table->flows[i].size; j++)
        {
            if (table->flows[i].packets[j].checksum == 0xf436)
            {
                printf("    Packet Data: %s\n", table->flows[i].packets[j].data);
                flow = &table->flows[i];
            }
        }
    }
    /*
    Iterate through all the packets in the TCP Flow and print the packet data
    if the packet data does not contain the string 'somewhere'
    and the packet data contains the string 'PASSWORD'
    */
    for (int i = 0; i < flow->size; i++)
    {
        if (strstr((char *)flow->packets[i].data, "somewhere") == NULL && strstr((char *)flow->packets[i].data, "PASSWORD") != NULL)
        {
            printf("    Packet Data: %s\n", flow->packets[i].data);
        }
    }
}

/* My device has an IP Address “123.134.156.178”.
Sum of my connection ports will lead you to a person. */
void four(FlowTable *table)
{
    int sum = 0;
    for (int i = 0; i < table->size; i++)
    {
        for (int j = 0; j < table->flows[i].size; j++)
        {
            if (table->flows[i].client == inet_addr("123.134.156.178"))
            {
                sum += table->flows[i].client_port;
                sum += table->flows[i].server_port;
            }
        }
    }
    printf("    Sum of connection ports: %d\n", sum);
    // search for the flow with the sum of connection ports as ports in the flow
    for (int i = 0; i < table->size; i++)
    {
        if (table->flows[i].client_port == sum || table->flows[i].server_port == sum)
        {
            // print all the packets in the flow
            for (int j = 0; j < table->flows[i].size; j++)
            {
                printf("    Packet Data: %s\n", table->flows[i].packets[j].data);
            }
        }
    }
}

/* I come from localhost, I requested a milkshake. Find my flavour. */
void five(FlowTable *table)
{
    // search for the flow with client IP as localhost
    for (int i = 0; i < table->size; i++)
    {
        if (table->flows[i].client == inet_addr("127.0.0.1"))
        {
            // print all the packets in the flow
            for (int j = 0; j < table->flows[i].size; j++)
            {
                printf("    Packet Data: %s\n", table->flows[i].packets[j].data);
            }
        }
    }
}

// Print the TCP Flow Table and its statistics
void print_clues(FlowTable *table)
{
    printf("Q1:\n");
    one(table);
    printf("\n");
    printf("Q2:\n");
    two(table);
    printf("\n");
    printf("Q3:\n");
    three(table);
    printf("\n");
    printf("Q4:\n");
    four(table);
    printf("\n");
    printf("Q5:\n");
    five(table);
    printf("\n");
}

// Global TCP Flow Table
FlowTable *table;

// Signal handler for ctrl+c
void signal_handler(int signal)
{
    if (signal == SIGINT)
    {
        print_clues(table);
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
