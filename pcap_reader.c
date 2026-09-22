#define _GNU_SOURCE
#include <stdio.h>
#include <pcap.h>
#include "svdpi.h"
#ifdef __cplusplus
extern "C" {
#endif

pcap_t *handle = NULL;
struct pcap_pkthdr header;
const u_char *packet_data = NULL;
int current_byte_idx = 0;

int open_pcap(const char* filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening PCAP file: %s\n", errbuf);
        return -1;
    }
    printf("[C-DPI] Successfully opened %s\n", filename);
    return 0;
}

int fetch_next_packet() {
    if (!handle) return 0;
    
    packet_data = pcap_next(handle, &header);
    if (packet_data == NULL) {
        pcap_close(handle);
        handle = NULL;
        return 0;
    }
    current_byte_idx = 0;
    return header.len;
}

unsigned char get_packet_byte() {
    if (!packet_data || current_byte_idx >= header.len) {
        return 0;
    }
    return packet_data[current_byte_idx++];
}

#ifdef __cplusplus
}
#endif

