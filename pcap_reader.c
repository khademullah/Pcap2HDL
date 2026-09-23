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
        packet_data = NULL;
        current_byte_idx = 0;
        return 0;
    }
    current_byte_idx = 0;
    /* caplen is stored bytes; header.len is original on-wire length. */
    return (int)header.caplen;
}

int get_wire_len(void) {
    return packet_data ? (int)header.len : 0;
}

long long get_ts_sec(void) {
    return packet_data ? (long long)header.ts.tv_sec : 0;
}

int get_ts_usec(void) {
    return packet_data ? (int)header.ts.tv_usec : 0;
}

int get_datalink(void) {
    return handle ? pcap_datalink(handle) : -1;
}

unsigned char get_packet_byte() {
    if (!packet_data || current_byte_idx >= (int)header.caplen) {
        return 0;
    }
    return packet_data[current_byte_idx++];
}

void close_pcap() {
    if (handle) {
        pcap_close(handle);
        handle = NULL;
    }
    packet_data = NULL;
    current_byte_idx = 0;
}

#ifdef __cplusplus
}
#endif

