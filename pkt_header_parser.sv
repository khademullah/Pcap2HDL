// Streaming Ethernet / IPv4 header parser.
// Byte 0 is the first beat after tstart (0-based, matching the wire format):
//   0-5   dest MAC
//   6-11  src MAC
//   12-13 EtherType
//   26-29 IPv4 src  (if EtherType == 0x0800, untagged)
//   30-33 IPv4 dst
// hdr_valid pulses once per frame: after L2 for non-IPv4, after IPs for IPv4,
// or on tlast if the frame is truncated.

`timescale 1ns/1ps

module pkt_header_parser (
    input  logic        clk,
    input  logic        rst_n,
    input  logic [7:0]  tdata,
    input  logic        tvalid,
    input  logic        tstart,
    input  logic        tlast,

    output logic        hdr_valid,
    output logic        is_ipv4,
    output logic        is_non_ipv4,
    output logic        is_truncated,
    output logic [47:0] dst_mac,
    output logic [47:0] src_mac,
    output logic [15:0] ethertype,
    output logic [31:0] src_ip,
    output logic [31:0] dst_ip
);

    localparam logic [15:0] ETYPE_IPV4 = 16'h0800;

    logic [15:0] byte_idx;
    logic        hdr_issued;
    logic        saw_ipv4;

    logic [15:0] cur_idx;
    logic [15:0] etype_now;

    always_comb begin
        cur_idx   = tstart ? 16'd0 : (byte_idx + 16'd1);
        etype_now = (cur_idx == 16'd13) ? {ethertype[15:8], tdata} : ethertype;
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            byte_idx     <= 16'd0;
            hdr_issued   <= 1'b0;
            saw_ipv4     <= 1'b0;
            hdr_valid    <= 1'b0;
            is_ipv4      <= 1'b0;
            is_non_ipv4  <= 1'b0;
            is_truncated <= 1'b0;
            dst_mac      <= 48'd0;
            src_mac      <= 48'd0;
            ethertype    <= 16'd0;
            src_ip       <= 32'd0;
            dst_ip       <= 32'd0;
        end else begin
            hdr_valid <= 1'b0;

            if (tvalid) begin
                if (tstart) begin
                    byte_idx     <= 16'd0;
                    hdr_issued   <= 1'b0;
                    saw_ipv4     <= 1'b0;
                    is_ipv4      <= 1'b0;
                    is_non_ipv4  <= 1'b0;
                    is_truncated <= 1'b0;
                    dst_mac      <= 48'd0;
                    src_mac      <= 48'd0;
                    ethertype    <= 16'd0;
                    src_ip       <= 32'd0;
                    dst_ip       <= 32'd0;
                end else begin
                    byte_idx <= cur_idx;
                end

                case (cur_idx)
                    16'd0:  dst_mac[47:40]    <= tdata;
                    16'd1:  dst_mac[39:32]    <= tdata;
                    16'd2:  dst_mac[31:24]    <= tdata;
                    16'd3:  dst_mac[23:16]    <= tdata;
                    16'd4:  dst_mac[15:8]     <= tdata;
                    16'd5:  dst_mac[7:0]      <= tdata;
                    16'd6:  src_mac[47:40]    <= tdata;
                    16'd7:  src_mac[39:32]    <= tdata;
                    16'd8:  src_mac[31:24]    <= tdata;
                    16'd9:  src_mac[23:16]    <= tdata;
                    16'd10: src_mac[15:8]     <= tdata;
                    16'd11: src_mac[7:0]      <= tdata;
                    16'd12: ethertype[15:8]   <= tdata;
                    16'd13: ethertype[7:0]    <= tdata;
                    16'd26: src_ip[31:24]     <= tdata;
                    16'd27: src_ip[23:16]     <= tdata;
                    16'd28: src_ip[15:8]      <= tdata;
                    16'd29: src_ip[7:0]       <= tdata;
                    16'd30: dst_ip[31:24]     <= tdata;
                    16'd31: dst_ip[23:16]     <= tdata;
                    16'd32: dst_ip[15:8]      <= tdata;
                    16'd33: dst_ip[7:0]       <= tdata;
                    default: ;
                endcase

                if (cur_idx == 16'd13)
                    saw_ipv4 <= (etype_now == ETYPE_IPV4);

                // tstart clears issued in NBA; allow emit on the first beat of a new frame.
                if (tstart || !hdr_issued) begin
                    if (cur_idx == 16'd13 && etype_now != ETYPE_IPV4) begin
                        emit_hdr(1'b0, 1'b1, 1'b0);
                    end else if (cur_idx == 16'd13 && tlast) begin
                        emit_hdr(1'b0, 1'b0, 1'b1);
                    end else if (cur_idx == 16'd33 && (saw_ipv4 || etype_now == ETYPE_IPV4)) begin
                        emit_hdr(1'b1, 1'b0, 1'b0);
                    end else if (tlast && cur_idx < 16'd13) begin
                        emit_hdr(1'b0, 1'b0, 1'b1);
                    end else if (tlast && saw_ipv4 && cur_idx < 16'd33) begin
                        emit_hdr(1'b0, 1'b0, 1'b1);
                    end
                end
            end
        end
    end

    task automatic emit_hdr(
        input logic ipv4,
        input logic non_ipv4,
        input logic trunc
    );
        hdr_valid    <= 1'b1;
        hdr_issued   <= 1'b1;
        is_ipv4      <= ipv4;
        is_non_ipv4  <= non_ipv4;
        is_truncated <= trunc;
    endtask

endmodule
