#include "flow_table.h"
#include <memory.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>

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
Flow *add_flow_to_table(FlowTable *table, uint32_t source, uint32_t destination, uint16_t source_port, uint16_t destination_port)
{
    if (table->size == table->capacity)
    {
        table->capacity *= 2;
        table->flows = (Flow *)realloc(table->flows, table->capacity * sizeof(Flow));
    }
    table->flows[table->size].source = source;
    table->flows[table->size].destination = destination;
    table->flows[table->size].source_port = source_port;
    table->flows[table->size].destination_port = destination_port;
    table->flows[table->size].size = 0;
    table->flows[table->size].capacity = 2;
    table->flows[table->size].packets = (Packet *)malloc(table->flows[table->size].capacity * sizeof(Packet));
    table->size++;
    return &table->flows[table->size - 1];
}

// Search for a TCP Flow in the TCP Flow Table
Flow *search_flow_in_table(FlowTable *table, uint32_t source, uint32_t destination, uint16_t source_port, uint16_t destination_port)
{
    for (int i = 0; i < table->size; i++)
    {
        if (table->flows[i].source == source && table->flows[i].destination == destination && table->flows[i].source_port == source_port && table->flows[i].destination_port == destination_port)
            return &table->flows[i];
    }
    return NULL;
}

// Print the TCP Flow Table
void *print_flow_table(FlowTable *table)
{
    int flow_number = 1;
    // Iterate through all the TCP Flows in the TCP Flow Table
    for (int i = 0; i < table->size; i++)
    {
        printf("Flow - %d\n", flow_number++);
        printf("  Source IP: %s\n", inet_ntoa(*(struct in_addr *)&table->flows[i].source));
        printf("  Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&table->flows[i].destination));
        printf("  Source Port: %d\n", table->flows[i].source_port);
        printf("  Destination Port: %d\n", table->flows[i].destination_port);
        printf("  Packets:\n");
        // Iterate through all the packets in the TCP Flow
        for (int j = 0; j < table->flows[i].size; j++)
        {
            printf("    Packet - %d\n", j + 1);
            printf("      Size: %d\n", table->flows[i].packets[j].size);
            printf("      Checksum: %d\n", table->flows[i].packets[j].checksum);
            printf("      Data: ");
            // Print the packet data
            for (int k = 0; k < table->flows[i].packets[j].size; k++)
            {
                printf("%c", table->flows[i].packets[j].data[k]);
            }
            printf("\n");
        }
    }
}

// Free the memory allocated to the TCP Flow Table
void free_flow_table(FlowTable *table)
{
    // Free the memory allocated for the TCP Flow Table
    for (int i = 0; i < table->size; i++)
    {
        for (int j = 0; j < table->flows[i].size; j++)
        {
            free(table->flows[i].packets[j].data);
        }
        free(table->flows[i].packets);
    }
    free(table->flows);
    free(table);
}