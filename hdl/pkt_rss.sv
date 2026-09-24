// NIC RSS: Microsoft Toeplitz hash of IPv4 4-tuple (TCP/UDP) or 2-tuple (other).
// Same 40-byte key and bit order as dpi/pcap_reader.c. Queue = hash % NUM_Q.

`timescale 1ns/1ps

module pkt_rss #(
    parameter int NUM_Q = 4
) (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        hdr_valid,
    input  logic        is_ipv4,
    input  logic        is_truncated,
    input  logic [7:0]  ip_proto,
    input  logic [31:0] src_ip,
    input  logic [31:0] dst_ip,
    input  logic [15:0] src_port,
    input  logic [15:0] dst_port,

    output logic        rss_valid,
    output logic        rss_skip,
    output logic [31:0] rss_hash,
    output logic [1:0]  rss_qid
);

    localparam logic [7:0] RSS_KEY [0:39] = '{
        8'h6d, 8'h5a, 8'h56, 8'hda, 8'h25, 8'h5b, 8'h0e, 8'hc2,
        8'h41, 8'h67, 8'h25, 8'h3d, 8'h43, 8'ha3, 8'h8f, 8'hb0,
        8'hd0, 8'hca, 8'h2b, 8'hcb, 8'hae, 8'h7b, 8'h30, 8'hb4,
        8'h77, 8'hcb, 8'h2d, 8'ha3, 8'h80, 8'h30, 8'hf2, 8'h0c,
        8'h6a, 8'h42, 8'hb7, 8'h3b, 8'hbe, 8'hac, 8'h01, 8'hfa
    };

    function automatic logic [31:0] key_window(input int bit_off);
        logic [31:0] v;
        int b, by, bi;
        v = 32'd0;
        for (int i = 0; i < 32; i++) begin
            b  = bit_off + i;
            by = b / 8;
            bi = 7 - (b % 8);
            v  = {v[30:0], RSS_KEY[by][bi]};
        end
        return v;
    endfunction

    function automatic logic [31:0] toeplitz(input logic [7:0] in [0:11], input int nbytes);
        logic [31:0] hash;
        int off;
        hash = 32'd0;
        off  = 0;
        for (int i = 0; i < nbytes; i++) begin
            for (int bi = 7; bi >= 0; bi--) begin
                if (in[i][bi])
                    hash = hash ^ key_window(off);
                off = off + 1;
            end
        end
        return hash;
    endfunction

    logic [7:0]  inb [0:11];
    logic [31:0] h;
    int          n;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rss_valid <= 1'b0;
            rss_skip  <= 1'b0;
            rss_hash  <= 32'd0;
            rss_qid   <= 2'd0;
        end else begin
            rss_valid <= 1'b0;
            rss_skip  <= 1'b0;
            if (hdr_valid) begin
                if (!is_ipv4 || is_truncated) begin
                    rss_skip <= 1'b1;
                end else begin
                    inb[0]  = src_ip[31:24];
                    inb[1]  = src_ip[23:16];
                    inb[2]  = src_ip[15:8];
                    inb[3]  = src_ip[7:0];
                    inb[4]  = dst_ip[31:24];
                    inb[5]  = dst_ip[23:16];
                    inb[6]  = dst_ip[15:8];
                    inb[7]  = dst_ip[7:0];
                    inb[8]  = src_port[15:8];
                    inb[9]  = src_port[7:0];
                    inb[10] = dst_port[15:8];
                    inb[11] = dst_port[7:0];
                    n = ((ip_proto == 8'd6) || (ip_proto == 8'd17)) ? 12 : 8;
                    h = toeplitz(inb, n);
                    rss_hash  <= h;
                    rss_qid   <= 2'(h % NUM_Q);
                    rss_valid <= 1'b1;
                end
            end
        end
    end

endmodule
