// TCP handshake tracker.
// One CAM entry per 4-tuple {src_ip, dst_ip, src_port, dst_port}. SYN-ACK and
// later reverse traffic look up the swapped tuple.

`timescale 1ns/1ps

module pkt_tcp_tracker #(
    parameter int NUM_SESS = 4
) (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        hdr_valid,
    input  logic        is_tcp,
    input  logic [31:0] src_ip,
    input  logic [31:0] dst_ip,
    input  logic [15:0] src_port,
    input  logic [15:0] dst_port,
    input  logic [31:0] seq,
    input  logic [31:0] ack,
    input  logic [7:0]  flags,

    output logic        evt_valid,
    output logic        syn_ok,
    output logic        synack_ok,
    output logic        hs_done,
    output logic        fin_ok,
    output logic        rst_ok,
    output logic        seq_err,
    output logic        op_err,
    output logic        sess_full
);

    typedef struct packed {
        logic        used;
        logic        syn_seen;
        logic        synack_seen;
        logic        established;
        logic [31:0] src_ip;
        logic [31:0] dst_ip;
        logic [15:0] src_port;
        logic [15:0] dst_port;
        logic [31:0] client_iss;
        logic [31:0] server_iss;
    } sess_t;

    sess_t sess [NUM_SESS];

    wire syn_bit = flags[1];
    wire rst_bit = flags[2];
    wire ack_bit = flags[4];
    wire fin_bit = flags[0];

    integer hit, rev, free_i, i;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            evt_valid  <= 1'b0;
            syn_ok     <= 1'b0;
            synack_ok  <= 1'b0;
            hs_done    <= 1'b0;
            fin_ok     <= 1'b0;
            rst_ok     <= 1'b0;
            seq_err    <= 1'b0;
            op_err     <= 1'b0;
            sess_full  <= 1'b0;
            for (i = 0; i < NUM_SESS; i = i + 1)
                sess[i] <= '0;
        end else begin
            evt_valid <= 1'b0;
            syn_ok    <= 1'b0;
            synack_ok <= 1'b0;
            hs_done   <= 1'b0;
            fin_ok    <= 1'b0;
            rst_ok    <= 1'b0;
            seq_err   <= 1'b0;
            op_err    <= 1'b0;
            sess_full <= 1'b0;

            if (hdr_valid && is_tcp) begin
                evt_valid <= 1'b1;
                hit    = -1;
                rev    = -1;
                free_i = -1;
                for (i = 0; i < NUM_SESS; i = i + 1) begin
                    if (sess[i].used &&
                        sess[i].src_ip == src_ip && sess[i].dst_ip == dst_ip &&
                        sess[i].src_port == src_port && sess[i].dst_port == dst_port)
                        hit = i;
                    if (sess[i].used &&
                        sess[i].src_ip == dst_ip && sess[i].dst_ip == src_ip &&
                        sess[i].src_port == dst_port && sess[i].dst_port == src_port)
                        rev = i;
                    if (!sess[i].used && free_i < 0)
                        free_i = i;
                end

                if (rst_bit) begin
                    rst_ok <= 1'b1;
                end else if (syn_bit && !ack_bit) begin
                    if (hit < 0) begin
                        if (free_i < 0) begin
                            sess_full <= 1'b1;
                            op_err    <= 1'b1;
                        end else begin
                            sess[free_i].used       <= 1'b1;
                            sess[free_i].syn_seen   <= 1'b1;
                            sess[free_i].src_ip     <= src_ip;
                            sess[free_i].dst_ip     <= dst_ip;
                            sess[free_i].src_port   <= src_port;
                            sess[free_i].dst_port   <= dst_port;
                            sess[free_i].client_iss <= seq;
                            syn_ok <= 1'b1;
                        end
                    end else if (sess[hit].syn_seen && !sess[hit].established) begin
                        sess[hit].client_iss <= seq;
                        syn_ok <= 1'b1;
                    end else begin
                        op_err <= 1'b1;
                    end
                end else if (syn_bit && ack_bit) begin
                    if (rev < 0 || !sess[rev].syn_seen) begin
                        op_err <= 1'b1;
                    end else if (ack != (sess[rev].client_iss + 32'd1)) begin
                        seq_err <= 1'b1;
                    end else begin
                        sess[rev].synack_seen <= 1'b1;
                        sess[rev].server_iss  <= seq;
                        synack_ok <= 1'b1;
                    end
                end else if (fin_bit &&
                             ((hit >= 0 && sess[hit].established) ||
                              (rev >= 0 && sess[rev].established))) begin
                    fin_ok <= 1'b1;
                end else if (ack_bit) begin
                    if (hit >= 0 && sess[hit].established) begin
                        ;
                    end else if (hit >= 0 && sess[hit].synack_seen) begin
                        if (ack != (sess[hit].server_iss + 32'd1))
                            seq_err <= 1'b1;
                        else begin
                            sess[hit].established <= 1'b1;
                            hs_done <= 1'b1;
                        end
                    end else if (rev >= 0 && sess[rev].established) begin
                        ;
                    end else begin
                        op_err <= 1'b1;
                    end
                end else begin
                    op_err <= 1'b1;
                end
            end
        end
    end

endmodule
