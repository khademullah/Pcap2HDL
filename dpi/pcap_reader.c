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

static struct bpf_program bpf_prog;
static int bpf_on;
static int bpf_skip;
static int bpf_match;

static void compute_rss(void);

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

    while (1) {
        packet_data = pcap_next(handle, &header);
        if (packet_data == NULL) {
            packet_data = NULL;
            current_byte_idx = 0;
            return 0;
        }
        if (bpf_on && pcap_offline_filter(&bpf_prog, &header, packet_data) == 0) {
            bpf_skip++;
            continue;
        }
        break;
    }
    current_byte_idx = 0;
    bpf_match++;
    /* caplen is stored bytes; header.len is original on-wire length. */
    compute_rss();
    return (int)header.caplen;
}

/* Compile BPF but do not pcap_setfilter: fetch_next_packet() applies
 * pcap_offline_filter so skipped frames can be counted. */
int set_pcap_filter(const char *filter) {
    if (!handle || !filter || filter[0] == '\0')
        return -1;
    if (bpf_on) {
        pcap_freecode(&bpf_prog);
        bpf_on = 0;
    }
    if (pcap_compile(handle, &bpf_prog, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "BPF compile failed: %s\n", pcap_geterr(handle));
        return -1;
    }
    bpf_on = 1;
    bpf_skip = 0;
    bpf_match = 0;
    printf("[C-DPI] BPF filter: %s\n", filter);
    return 0;
}

int get_bpf_match(void) {
    return bpf_match;
}

int get_bpf_skip(void) {
    return bpf_skip;
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

/* Intel/Microsoft RSS Toeplitz. Same key and bit order as pkt_rss.sv. */
static const unsigned char rss_key[40] = {
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
    0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
    0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
    0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
    0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa
};

static int rss_valid;
static unsigned int rss_hash_val;

static unsigned int rss_key_window(int bit_off)
{
    unsigned int v = 0;
    int i, b, by, bi;

    for (i = 0; i < 32; i++) {
        b = bit_off + i;
        by = b / 8;
        bi = 7 - (b % 8);
        v <<= 1;
        if (rss_key[by] & (1u << bi))
            v |= 1u;
    }
    return v;
}

static unsigned int rss_toeplitz(const unsigned char *in, int nbytes)
{
    unsigned int hash = 0;
    int off = 0, i, bit;

    for (i = 0; i < nbytes; i++) {
        for (bit = 7; bit >= 0; bit--) {
            if (in[i] & (1u << bit))
                hash ^= rss_key_window(off);
            off++;
        }
    }
    return hash;
}

static void compute_rss(void)
{
    unsigned char in[12];
    int ihl, l4, cap;
    unsigned et;

    rss_valid = 0;
    rss_hash_val = 0;
    if (!packet_data)
        return;
    cap = (int)header.caplen;
    if (cap < 34)
        return;
    et = ((unsigned)packet_data[12] << 8) | packet_data[13];
    if (et != 0x0800)
        return;
    ihl = packet_data[14] & 0x0f;
    if (ihl < 5)
        return;
    l4 = 14 + ihl * 4;
    in[0] = packet_data[26];
    in[1] = packet_data[27];
    in[2] = packet_data[28];
    in[3] = packet_data[29];
    in[4] = packet_data[30];
    in[5] = packet_data[31];
    in[6] = packet_data[32];
    in[7] = packet_data[33];
    if ((packet_data[23] == 6 || packet_data[23] == 17) && cap >= l4 + 4) {
        in[8]  = packet_data[l4];
        in[9]  = packet_data[l4 + 1];
        in[10] = packet_data[l4 + 2];
        in[11] = packet_data[l4 + 3];
        rss_hash_val = rss_toeplitz(in, 12);
    } else {
        rss_hash_val = rss_toeplitz(in, 8);
    }
    rss_valid = 1;
}

int get_rss_valid(void)
{
    return rss_valid;
}

unsigned int get_rss_hash(void)
{
    return rss_hash_val;
}

unsigned char get_packet_byte() {
    if (!packet_data || current_byte_idx >= (int)header.caplen) {
        return 0;
    }
    return packet_data[current_byte_idx++];
}

void close_pcap() {
    if (bpf_on) {
        pcap_freecode(&bpf_prog);
        bpf_on = 0;
    }
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

