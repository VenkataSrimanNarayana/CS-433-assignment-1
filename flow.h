#ifndef FLOW_H
#define FLOW_H
#include <stdint.h>

// Packet structure
typedef struct
{
    unsigned char *data;
    int size;
    uint16_t checksum;
} Packet;

// TCP FLow structure
typedef struct
{
    uint32_t source, destination;
    uint16_t source_port, destination_port;
    int size;
    int capacity;
    Packet *packets;
} Flow;

void add_packet_data_to_flow(Flow *flow, unsigned char *data, int size, uint16_t checksum);
#endif