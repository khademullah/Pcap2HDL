#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include "svdpi.h"
#ifdef __cplusplus
extern "C" {
#endif

pcap_t *handle = NULL;
pcap_t *dump_dead = NULL;
pcap_dumper_t *dumper = NULL;
struct pcap_pkthdr header;
const u_char *packet_data = NULL;
int current_byte_idx = 0;

#define DUMP_MAX 65535
static u_char dump_buf[DUMP_MAX];
static int dump_len = 0;
static int dump_count = 0;

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

/* libpcap BPF on the offline handle. pcap_next() then skips non-matching
 * frames so HDL only sees the slice (tcp port 5201, udp port 4791, ...). */
int set_pcap_filter(const char *filter) {
    struct bpf_program fp;

    if (!handle || !filter || filter[0] == '\0')
        return -1;
    if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "BPF compile failed: %s\n", pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "BPF setfilter failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        return -1;
    }
    pcap_freecode(&fp);
    printf("[C-DPI] BPF filter: %s\n", filter);
    return 0;
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

int open_pcap_dump(const char *filename, int linktype) {
    if (!filename || filename[0] == '\0')
        return -1;
    dump_dead = pcap_open_dead(linktype, DUMP_MAX);
    if (!dump_dead) {
        fprintf(stderr, "Error creating dump session\n");
        return -1;
    }
    dumper = pcap_dump_open(dump_dead, filename);
    if (!dumper) {
        fprintf(stderr, "Error opening dump %s: %s\n", filename, pcap_geterr(dump_dead));
        pcap_close(dump_dead);
        dump_dead = NULL;
        return -1;
    }
    dump_len = 0;
    dump_count = 0;
    printf("[C-DPI] Dumping AXI-Stream to %s (DLT=%d)\n", filename, linktype);
    return 0;
}

void dump_put_byte(unsigned char b) {
    if (!dumper)
        return;
    if (dump_len < DUMP_MAX)
        dump_buf[dump_len++] = b;
}

int dump_packet(long long ts_sec, int ts_usec, int wire_len) {
    struct pcap_pkthdr h;

    if (!dumper)
        return -1;
    h.ts.tv_sec = (time_t)ts_sec;
    h.ts.tv_usec = ts_usec;
    h.caplen = (bpf_u_int32)dump_len;
    if (wire_len > dump_len)
        h.len = (bpf_u_int32)wire_len;
    else
        h.len = (bpf_u_int32)dump_len;
    pcap_dump((u_char *)dumper, &h, dump_buf);
    dump_count++;
    dump_len = 0;
    return 0;
}

int dump_pkt_count(void) {
    return dump_count;
}

void close_pcap_dump(void) {
    if (dumper) {
        pcap_dump_flush(dumper);
        pcap_dump_close(dumper);
        dumper = NULL;
    }
    if (dump_dead) {
        pcap_close(dump_dead);
        dump_dead = NULL;
    }
    dump_len = 0;
}

#ifdef __cplusplus
}
#endif

