#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H
#include "flow.h"
// Define a TCP Flow Table
typedef struct
{
    Flow *flows;
    int size;
    int capacity;
} FlowTable;

FlowTable *init_flow_table();
void add_flow(FlowTable *table, Flow flow);
Flow *add_flow_to_table(FlowTable *table, uint32_t client, uint32_t server, uint16_t client_port, uint16_t server_port);
Flow *search_flow_in_table(FlowTable *table, uint32_t client, uint32_t server, uint16_t client_port, uint16_t server_port);
void *print_flow_table(FlowTable *table);
void free_flow_table(FlowTable *table);
#endif