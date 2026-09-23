// Streaming Ethernet / IPv4 / L4 parser.
// Soft-RoCEv2 = IPv4 + UDP port 4791. Soft-RoCEv1 = EtherType 0x8915.

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
    output logic        is_tcp,
    output logic        is_udp,
    output logic        is_roce,
    output logic [47:0] dst_mac,
    output logic [47:0] src_mac,
    output logic [15:0] ethertype,
    output logic [31:0] src_ip,
    output logic [31:0] dst_ip,
    output logic [7:0]  ip_proto,
    output logic [15:0] src_port,
    output logic [15:0] dst_port,
    output logic [7:0]  bth_opcode,
    output logic [23:0] dest_qp,
    output logic [23:0] bth_psn
);

    localparam logic [15:0] ETYPE_IPV4   = 16'h0800;
    localparam logic [15:0] ETYPE_ROCEV1 = 16'h8915;
    localparam logic [7:0]  PROTO_TCP    = 8'd6;
    localparam logic [7:0]  PROTO_UDP    = 8'd17;
    localparam logic [15:0] PORT_ROCEV2  = 16'd4791;

    logic [15:0] byte_idx;
    logic        hdr_issued;
    logic        saw_ipv4;
    logic [3:0]  ip_ihl;

    logic [15:0] cur_idx;
    logic [15:0] etype_now;
    logic [15:0] l4_off;
    logic [15:0] l4_last;
    logic [15:0] bth_off;
    logic [15:0] bth_last;
    logic        needs_ports;
    logic [15:0] dst_port_now;
    logic        roce_now;

    always_comb begin
        cur_idx      = tstart ? 16'd0 : (byte_idx + 16'd1);
        etype_now    = (cur_idx == 16'd13) ? {ethertype[15:8], tdata} : ethertype;
        l4_off       = 16'd14 + {10'd0, ip_ihl, 2'b00};
        l4_last      = l4_off + 16'd3;
        bth_off      = l4_off + 16'd8;
        bth_last     = bth_off + 16'd11;
        needs_ports  = (ip_proto == PROTO_TCP) || (ip_proto == PROTO_UDP);
        dst_port_now = (cur_idx == l4_last) ? {dst_port[15:8], tdata} : dst_port;
        roce_now     = (etype_now == ETYPE_ROCEV1) ||
                       ((ip_proto == PROTO_UDP) &&
                        ((src_port == PORT_ROCEV2) || (dst_port_now == PORT_ROCEV2)));
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            byte_idx     <= 16'd0;
            hdr_issued   <= 1'b0;
            saw_ipv4     <= 1'b0;
            ip_ihl       <= 4'd5;
            hdr_valid    <= 1'b0;
            is_ipv4      <= 1'b0;
            is_non_ipv4  <= 1'b0;
            is_truncated <= 1'b0;
            is_tcp       <= 1'b0;
            is_udp       <= 1'b0;
            is_roce      <= 1'b0;
            dst_mac      <= 48'd0;
            src_mac      <= 48'd0;
            ethertype    <= 16'd0;
            src_ip       <= 32'd0;
            dst_ip       <= 32'd0;
            ip_proto     <= 8'd0;
            src_port     <= 16'd0;
            dst_port     <= 16'd0;
            bth_opcode   <= 8'd0;
            dest_qp      <= 24'd0;
            bth_psn      <= 24'd0;
        end else begin
            hdr_valid <= 1'b0;

            if (tvalid) begin
                if (tstart) begin
                    byte_idx     <= 16'd0;
                    hdr_issued   <= 1'b0;
                    saw_ipv4     <= 1'b0;
                    ip_ihl       <= 4'd5;
                    is_ipv4      <= 1'b0;
                    is_non_ipv4  <= 1'b0;
                    is_truncated <= 1'b0;
                    is_tcp       <= 1'b0;
                    is_udp       <= 1'b0;
                    is_roce      <= 1'b0;
                    dst_mac      <= 48'd0;
                    src_mac      <= 48'd0;
                    ethertype    <= 16'd0;
                    src_ip       <= 32'd0;
                    dst_ip       <= 32'd0;
                    ip_proto     <= 8'd0;
                    src_port     <= 16'd0;
                    dst_port     <= 16'd0;
                    bth_opcode   <= 8'd0;
                    dest_qp      <= 24'd0;
                    bth_psn      <= 24'd0;
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
                    16'd14: ip_ihl            <= tdata[3:0];
                    16'd23: ip_proto          <= tdata;
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

                if (saw_ipv4) begin
                    if (cur_idx == l4_off)
                        src_port[15:8] <= tdata;
                    else if (cur_idx == (l4_off + 16'd1))
                        src_port[7:0]  <= tdata;
                    else if (cur_idx == (l4_off + 16'd2))
                        dst_port[15:8] <= tdata;
                    else if (cur_idx == (l4_off + 16'd3))
                        dst_port[7:0]  <= tdata;
                    else if (cur_idx == bth_off)
                        bth_opcode <= tdata;
                    else if (cur_idx == (bth_off + 16'd5))
                        dest_qp[23:16] <= tdata;
                    else if (cur_idx == (bth_off + 16'd6))
                        dest_qp[15:8]  <= tdata;
                    else if (cur_idx == (bth_off + 16'd7))
                        dest_qp[7:0]   <= tdata;
                    else if (cur_idx == (bth_off + 16'd9))
                        bth_psn[23:16] <= tdata;
                    else if (cur_idx == (bth_off + 16'd10))
                        bth_psn[15:8]  <= tdata;
                    else if (cur_idx == (bth_off + 16'd11))
                        bth_psn[7:0]   <= tdata;
                end

                if (cur_idx == 16'd13)
                    saw_ipv4 <= (etype_now == ETYPE_IPV4);

                if (tstart || !hdr_issued) begin
                    if (cur_idx == 16'd13 && etype_now != ETYPE_IPV4) begin
                        emit_hdr(1'b0, 1'b1, 1'b0);
                    end else if (cur_idx == 16'd13 && tlast) begin
                        emit_hdr(1'b0, 1'b0, 1'b1);
                    end else if (saw_ipv4 && needs_ports && !roce_now && cur_idx == l4_last) begin
                        emit_hdr(1'b1, 1'b0, 1'b0);
                    end else if (saw_ipv4 && roce_now && cur_idx == bth_last) begin
                        emit_hdr(1'b1, 1'b0, 1'b0);
                    end else if (saw_ipv4 && !needs_ports && cur_idx == 16'd33) begin
                        emit_hdr(1'b1, 1'b0, 1'b0);
                    end else if (tlast && cur_idx < 16'd13) begin
                        emit_hdr(1'b0, 1'b0, 1'b1);
                    end else if (tlast && saw_ipv4 && roce_now && cur_idx < bth_last) begin
                        emit_hdr(1'b0, 1'b0, 1'b1);
                    end else if (tlast && saw_ipv4 && needs_ports && !roce_now && cur_idx < l4_last) begin
                        emit_hdr(1'b0, 1'b0, 1'b1);
                    end else if (tlast && saw_ipv4 && !needs_ports && cur_idx < 16'd33) begin
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
        is_tcp       <= ipv4 && (ip_proto == PROTO_TCP);
        is_udp       <= ipv4 && (ip_proto == PROTO_UDP) && !roce_now;
        is_roce      <= roce_now;
    endtask

endmodule
