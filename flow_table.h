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
Flow *add_flow_to_table(FlowTable *table, uint32_t source, uint32_t destination, uint16_t source_port, uint16_t destination_port);
Flow *search_flow_in_table(FlowTable *table, uint32_t source, uint32_t destination, uint16_t source_port, uint16_t destination_port);
void *print_flow_table(FlowTable *table);
void free_flow_table(FlowTable *table);
#endif