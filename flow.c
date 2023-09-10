#include "flow.h"
#include <memory.h>
#include <stdlib.h>

// Add a new packet data to a TCP Flow
void add_packet_data_to_flow(Flow *flow, unsigned char *data, int size, uint16_t checksum)
{
    if (flow->size == flow->capacity)
    {
        flow->capacity *= 2;
        flow->packets = (Packet *)realloc(flow->packets, flow->capacity * sizeof(Packet));
    }
    flow->packets[flow->size].data = (unsigned char *)malloc(size * sizeof(unsigned char));
    memcpy(flow->packets[flow->size].data, data, size);
    // remove null bytes present in the data
    for (int i = 0; i < size; i++)
    {
        if (flow->packets[flow->size].data[i] == '\0')
        {
            flow->packets[flow->size].data[i] = ' ';
        }
    }
    flow->packets[flow->size].size = size;
    flow->packets[flow->size].checksum = checksum;
    flow->size++;
}