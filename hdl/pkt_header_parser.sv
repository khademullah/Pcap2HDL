// Streaming Ethernet / 802.1Q / IPv4 / IPv6 / L4 parser.
// One VLAN tag (EtherType 0x8100); QinQ is not handled. L3 starts at 14 or 18.
// IPv6 is the 40-byte base header only (no hop-by-hop / routing / fragment).
// Soft-RoCEv2 = IPv4 + UDP port 4791. Soft-RoCEv1 = EtherType 0x8915.
// ARP = 0x0806. VXLAN = UDP dest 4789 (inner Ethernet + VNI).
// DATA_W=8 is one byte per cycle; DATA_W=64 walks tkeep lanes in one beat.
// Beats are accepted only when tvalid && tready.

`timescale 1ns/1ps

module pkt_header_parser #(
    parameter int DATA_W = 8
) (
    input  logic                clk,
    input  logic                rst_n,
    input  logic [DATA_W-1:0]   tdata,
    input  logic [DATA_W/8-1:0] tkeep,
    input  logic                tvalid,
    input  logic                tready,
    input  logic                tstart,
    input  logic                tlast,

    output logic        hdr_valid,
    output logic        is_ipv4,
    output logic        is_ipv6,
    output logic        is_vlan,
    output logic [11:0] vlan_id,
    output logic        is_non_ipv4,
    output logic        is_truncated,
    output logic        is_tcp,
    output logic        is_udp,
    output logic        is_roce,
    output logic        is_arp,
    output logic        is_vxlan,
    output logic [23:0] vxlan_vni,
    output logic [47:0] dst_mac,
    output logic [47:0] src_mac,
    output logic [15:0] ethertype,
    output logic [31:0] src_ip,
    output logic [31:0] dst_ip,
    output logic [127:0] src_ip6,
    output logic [127:0] dst_ip6,
    output logic [7:0]  ip_ttl,
    output logic [15:0] ip_tot_len,
    output logic        is_len_mismatch,
    output logic [7:0]  ip_proto,
    output logic [15:0] src_port,
    output logic [15:0] dst_port,
    output logic [31:0] tcp_seq,
    output logic [31:0] tcp_ack,
    output logic [7:0]  tcp_flags,
    output logic [15:0] tcp_plen,
    output logic [7:0]  bth_opcode,
    output logic [15:0] bth_pkey,
    output logic        bth_ackreq,
    output logic [23:0] dest_qp,
    output logic [23:0] bth_psn
);

    localparam int KEEP_W = DATA_W / 8;
    localparam logic [15:0] ETYPE_IPV4   = 16'h0800;
    localparam logic [15:0] ETYPE_IPV6   = 16'h86DD;
    localparam logic [15:0] ETYPE_VLAN   = 16'h8100;
    localparam logic [15:0] ETYPE_ARP    = 16'h0806;
    localparam logic [15:0] ETYPE_ROCEV1 = 16'h8915;
    localparam logic [7:0]  PROTO_TCP    = 8'd6;
    localparam logic [7:0]  PROTO_UDP    = 8'd17;
    localparam logic [15:0] PORT_ROCEV2  = 16'd4791;
    localparam logic [15:0] PORT_VXLAN   = 16'd4789;

    logic [15:0] byte_idx;
    logic        hdr_issued;
    logic        saw_ipv4;
    logic        saw_ipv6;
    logic        saw_vlan;
    logic [15:0] vlan_tci;
    logic [15:0] vlan_etype;
    logic [3:0]  ip_ihl;
    logic [3:0]  tcp_doff;

    logic [15:0] idx_w;
    logic [7:0]  b_w;
    logic        last_b;
    logic        more_keep;
    logic        hdr_issued_w;
    logic        saw_ipv4_w;
    logic        saw_ipv6_w;
    logic        saw_vlan_w;
    logic [15:0] vlan_tci_w;
    logic [15:0] vlan_etype_w;
    logic [15:0] l3_w;
    logic [127:0] src_ip6_w;
    logic [127:0] dst_ip6_w;
    logic        is_ipv6_w;
    logic        saw_l3_w;
    logic [3:0]  ip_ihl_w;
    logic [47:0] dst_mac_w;
    logic [47:0] src_mac_w;
    logic [15:0] ethertype_w;
    logic [31:0] src_ip_w;
    logic [31:0] dst_ip_w;
    logic [7:0]  ip_ttl_w;
    logic [15:0] ip_tot_len_w;
    logic [7:0]  ip_proto_w;
    logic [15:0] src_port_w;
    logic [15:0] dst_port_w;
    logic [31:0] tcp_seq_w;
    logic [31:0] tcp_ack_w;
    logic [7:0]  tcp_flags_w;
    logic [3:0]  tcp_doff_w;
    logic [15:0] tcp_plen_w;
    logic [15:0] iph_w;
    logic [15:0] tcph_w;
    logic [7:0]  bth_opcode_w;
    logic [15:0] bth_pkey_w;
    logic        bth_ackreq_w;
    logic [23:0] dest_qp_w;
    logic [23:0] bth_psn_w;
    logic        hdr_valid_w;
    logic        is_ipv4_w;
    logic        is_non_ipv4_w;
    logic        is_truncated_w;
    logic        is_tcp_w;
    logic        is_udp_w;
    logic        is_roce_w;
    logic        is_arp_w;
    logic        is_vxlan_w;
    logic [23:0] vxlan_vni_w;
    logic        is_len_mis_w;
    logic [15:0] l4_off_w;
    logic [15:0] l4_last_w;
    logic [15:0] tcp_last_w;
    logic [15:0] bth_off_w;
    logic [15:0] bth_last_w;
    logic        needs_ports_w;
    logic        is_tcp_now_w;
    logic        roce_now_w;
    logic        vxlan_now_w;
    logic [15:0] vxlan_last_w;
    logic [15:0] inner_et_w;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            byte_idx     <= 16'd0;
            hdr_issued   <= 1'b0;
            saw_ipv4     <= 1'b0;
            saw_ipv6     <= 1'b0;
            saw_vlan     <= 1'b0;
            vlan_tci     <= 16'd0;
            vlan_etype   <= 16'd0;
            ip_ihl       <= 4'd5;
            tcp_doff     <= 4'd5;
            hdr_valid    <= 1'b0;
            is_ipv4      <= 1'b0;
            is_ipv6      <= 1'b0;
            is_vlan      <= 1'b0;
            vlan_id      <= 12'd0;
            is_non_ipv4  <= 1'b0;
            is_truncated <= 1'b0;
            is_tcp       <= 1'b0;
            is_udp       <= 1'b0;
            is_roce      <= 1'b0;
            is_arp       <= 1'b0;
            is_vxlan     <= 1'b0;
            vxlan_vni    <= 24'd0;
            dst_mac      <= 48'd0;
            src_mac      <= 48'd0;
            ethertype    <= 16'd0;
            src_ip       <= 32'd0;
            dst_ip       <= 32'd0;
            src_ip6      <= 128'd0;
            dst_ip6      <= 128'd0;
            ip_ttl       <= 8'd0;
            ip_tot_len   <= 16'd0;
            is_len_mismatch <= 1'b0;
            ip_proto     <= 8'd0;
            src_port     <= 16'd0;
            dst_port     <= 16'd0;
            tcp_seq      <= 32'd0;
            tcp_ack      <= 32'd0;
            tcp_flags    <= 8'd0;
            tcp_plen     <= 16'd0;
            bth_opcode   <= 8'd0;
            bth_pkey     <= 16'd0;
            bth_ackreq   <= 1'b0;
            dest_qp      <= 24'd0;
            bth_psn      <= 24'd0;
        end else begin
            hdr_valid       <= 1'b0;
            is_len_mismatch <= 1'b0;

            if (tvalid && tready) begin
                if (tstart) begin
                    idx_w         = 16'd0;
                    hdr_issued_w  = 1'b0;
                    saw_ipv4_w    = 1'b0;
                    saw_ipv6_w    = 1'b0;
                    saw_vlan_w    = 1'b0;
                    vlan_tci_w    = 16'd0;
                    vlan_etype_w  = 16'd0;
                    src_ip6_w     = 128'd0;
                    dst_ip6_w     = 128'd0;
                    ip_ihl_w      = 4'd5;
                    dst_mac_w     = 48'd0;
                    src_mac_w     = 48'd0;
                    ethertype_w   = 16'd0;
                    src_ip_w      = 32'd0;
                    dst_ip_w      = 32'd0;
                    ip_ttl_w      = 8'd0;
                    ip_tot_len_w  = 16'd0;
                    ip_proto_w    = 8'd0;
                    src_port_w    = 16'd0;
                    dst_port_w    = 16'd0;
                    tcp_seq_w     = 32'd0;
                    tcp_ack_w     = 32'd0;
                    tcp_flags_w   = 8'd0;
                    tcp_doff_w    = 4'd5;
                    bth_opcode_w  = 8'd0;
                    bth_pkey_w    = 16'd0;
                    bth_ackreq_w  = 1'b0;
                    dest_qp_w     = 24'd0;
                    bth_psn_w     = 24'd0;
                    is_ipv4_w     = 1'b0;
                    is_ipv6_w     = 1'b0;
                    is_non_ipv4_w = 1'b0;
                    is_truncated_w= 1'b0;
                    is_tcp_w      = 1'b0;
                    is_udp_w      = 1'b0;
                    is_roce_w     = 1'b0;
                    is_arp_w      = 1'b0;
                    is_vxlan_w    = 1'b0;
                    vxlan_vni_w   = 24'd0;
                    inner_et_w    = 16'd0;
                end else begin
                    idx_w         = byte_idx;
                    hdr_issued_w  = hdr_issued;
                    saw_ipv4_w    = saw_ipv4;
                    saw_ipv6_w    = saw_ipv6;
                    saw_vlan_w    = saw_vlan;
                    vlan_tci_w    = vlan_tci;
                    vlan_etype_w  = vlan_etype;
                    src_ip6_w     = src_ip6;
                    dst_ip6_w     = dst_ip6;
                    ip_ihl_w      = ip_ihl;
                    dst_mac_w     = dst_mac;
                    src_mac_w     = src_mac;
                    ethertype_w   = ethertype;
                    src_ip_w      = src_ip;
                    dst_ip_w      = dst_ip;
                    ip_ttl_w      = ip_ttl;
                    ip_tot_len_w  = ip_tot_len;
                    ip_proto_w    = ip_proto;
                    src_port_w    = src_port;
                    dst_port_w    = dst_port;
                    tcp_seq_w     = tcp_seq;
                    tcp_ack_w     = tcp_ack;
                    tcp_flags_w   = tcp_flags;
                    tcp_doff_w    = tcp_doff;
                    bth_opcode_w  = bth_opcode;
                    bth_pkey_w    = bth_pkey;
                    bth_ackreq_w  = bth_ackreq;
                    dest_qp_w     = dest_qp;
                    bth_psn_w     = bth_psn;
                    is_ipv4_w     = is_ipv4;
                    is_ipv6_w     = is_ipv6;
                    is_non_ipv4_w = is_non_ipv4;
                    is_truncated_w= is_truncated;
                    is_tcp_w      = is_tcp;
                    is_udp_w      = is_udp;
                    is_roce_w     = is_roce;
                    is_arp_w      = is_arp;
                    is_vxlan_w    = is_vxlan;
                    vxlan_vni_w   = vxlan_vni;
                    inner_et_w    = 16'd0;
                end

                hdr_valid_w  = 1'b0;
                is_len_mis_w = 1'b0;

                for (int lane = 0; lane < KEEP_W; lane++) begin
                    if (tkeep[lane]) begin
                        b_w = tdata[8*lane +: 8];
                        more_keep = 1'b0;
                        for (int j = lane + 1; j < KEEP_W; j++)
                            if (tkeep[j])
                                more_keep = 1'b1;
                        last_b = tlast && !more_keep;

                        unique case (idx_w)
                            16'd0:  dst_mac_w[47:40]  = b_w;
                            16'd1:  dst_mac_w[39:32]  = b_w;
                            16'd2:  dst_mac_w[31:24]  = b_w;
                            16'd3:  dst_mac_w[23:16]  = b_w;
                            16'd4:  dst_mac_w[15:8]   = b_w;
                            16'd5:  dst_mac_w[7:0]    = b_w;
                            16'd6:  src_mac_w[47:40]  = b_w;
                            16'd7:  src_mac_w[39:32]  = b_w;
                            16'd8:  src_mac_w[31:24]  = b_w;
                            16'd9:  src_mac_w[23:16]  = b_w;
                            16'd10: src_mac_w[15:8]   = b_w;
                            16'd11: src_mac_w[7:0]    = b_w;
                            16'd12: ethertype_w[15:8] = b_w;
                            16'd13: ethertype_w[7:0]  = b_w;
                            default: ;
                        endcase

                        if (idx_w == 16'd13) begin
                            saw_vlan_w = (ethertype_w == ETYPE_VLAN);
                            if (!saw_vlan_w) begin
                                saw_ipv4_w = (ethertype_w == ETYPE_IPV4);
                                saw_ipv6_w = (ethertype_w == ETYPE_IPV6);
                            end
                        end

                        if (saw_vlan_w) begin
                            unique case (idx_w)
                                16'd14: vlan_tci_w[15:8]   = b_w;
                                16'd15: vlan_tci_w[7:0]    = b_w;
                                16'd16: vlan_etype_w[15:8] = b_w;
                                16'd17: vlan_etype_w[7:0]  = b_w;
                                default: ;
                            endcase
                            if (idx_w == 16'd17) begin
                                saw_ipv4_w = (vlan_etype_w == ETYPE_IPV4);
                                saw_ipv6_w = (vlan_etype_w == ETYPE_IPV6);
                            end
                        end

                        l3_w = saw_vlan_w ? 16'd18 : 16'd14;
                        saw_l3_w = saw_ipv4_w || saw_ipv6_w;
                        if (saw_ipv6_w)
                            l4_off_w = l3_w + 16'd40;
                        else
                            l4_off_w = l3_w + {10'd0, ip_ihl_w, 2'b00};
                        l4_last_w     = l4_off_w + 16'd3;
                        tcp_last_w    = l4_off_w + 16'd13;
                        bth_off_w     = l4_off_w + 16'd8;
                        bth_last_w    = bth_off_w + 16'd11;
                        needs_ports_w = (ip_proto_w == PROTO_TCP) || (ip_proto_w == PROTO_UDP);
                        is_tcp_now_w  = (ip_proto_w == PROTO_TCP);

                        if (saw_ipv4_w && (idx_w >= l3_w)) begin
                            unique case (idx_w - l3_w)
                                16'd0:  ip_ihl_w           = b_w[3:0];
                                16'd2:  ip_tot_len_w[15:8] = b_w;
                                16'd3:  ip_tot_len_w[7:0]  = b_w;
                                16'd8:  ip_ttl_w           = b_w;
                                16'd9:  ip_proto_w         = b_w;
                                16'd12: src_ip_w[31:24]    = b_w;
                                16'd13: src_ip_w[23:16]    = b_w;
                                16'd14: src_ip_w[15:8]     = b_w;
                                16'd15: src_ip_w[7:0]      = b_w;
                                16'd16: dst_ip_w[31:24]    = b_w;
                                16'd17: dst_ip_w[23:16]    = b_w;
                                16'd18: dst_ip_w[15:8]     = b_w;
                                16'd19: dst_ip_w[7:0]      = b_w;
                                default: ;
                            endcase
                            src_ip6_w = {80'd0, 16'hffff, src_ip_w};
                            dst_ip6_w = {80'd0, 16'hffff, dst_ip_w};
                        end

                        if (saw_ipv6_w && (idx_w >= l3_w)) begin
                            unique case (idx_w - l3_w)
                                16'd4: ip_tot_len_w[15:8] = b_w;
                                16'd5: begin
                                    ip_tot_len_w[7:0] = b_w;
                                    ip_tot_len_w = 16'd40 + ip_tot_len_w;
                                end
                                16'd6: ip_proto_w = b_w;
                                16'd7: ip_ttl_w   = b_w;
                                default: ;
                            endcase
                            if ((idx_w >= (l3_w + 16'd8)) && (idx_w <= (l3_w + 16'd23)))
                                src_ip6_w[8*((l3_w + 16'd23) - idx_w) +: 8] = b_w;
                            if ((idx_w >= (l3_w + 16'd24)) && (idx_w <= (l3_w + 16'd39)))
                                dst_ip6_w[8*((l3_w + 16'd39) - idx_w) +: 8] = b_w;
                            src_ip_w = src_ip6_w[31:0];
                            dst_ip_w = dst_ip6_w[31:0];
                        end

                        l4_off_w      = saw_ipv6_w ? (l3_w + 16'd40) :
                                        (l3_w + {10'd0, ip_ihl_w, 2'b00});
                        l4_last_w     = l4_off_w + 16'd3;
                        tcp_last_w    = l4_off_w + 16'd13;
                        bth_off_w     = l4_off_w + 16'd8;
                        bth_last_w    = bth_off_w + 16'd11;
                        needs_ports_w = (ip_proto_w == PROTO_TCP) || (ip_proto_w == PROTO_UDP);
                        is_tcp_now_w  = (ip_proto_w == PROTO_TCP);

                        if (saw_l3_w) begin
                            if (idx_w == l4_off_w)
                                src_port_w[15:8] = b_w;
                            else if (idx_w == (l4_off_w + 16'd1))
                                src_port_w[7:0]  = b_w;
                            else if (idx_w == (l4_off_w + 16'd2))
                                dst_port_w[15:8] = b_w;
                            else if (idx_w == (l4_off_w + 16'd3))
                                dst_port_w[7:0]  = b_w;
                            else if (is_tcp_now_w && (idx_w == (l4_off_w + 16'd4)))
                                tcp_seq_w[31:24] = b_w;
                            else if (is_tcp_now_w && (idx_w == (l4_off_w + 16'd5)))
                                tcp_seq_w[23:16] = b_w;
                            else if (is_tcp_now_w && (idx_w == (l4_off_w + 16'd6)))
                                tcp_seq_w[15:8]  = b_w;
                            else if (is_tcp_now_w && (idx_w == (l4_off_w + 16'd7)))
                                tcp_seq_w[7:0]   = b_w;
                            else if (is_tcp_now_w && (idx_w == (l4_off_w + 16'd8)))
                                tcp_ack_w[31:24] = b_w;
                            else if (is_tcp_now_w && (idx_w == (l4_off_w + 16'd9)))
                                tcp_ack_w[23:16] = b_w;
                            else if (is_tcp_now_w && (idx_w == (l4_off_w + 16'd10)))
                                tcp_ack_w[15:8]  = b_w;
                            else if (is_tcp_now_w && (idx_w == (l4_off_w + 16'd11)))
                                tcp_ack_w[7:0]   = b_w;
                            else if (is_tcp_now_w && (idx_w == (l4_off_w + 16'd12)))
                                tcp_doff_w       = (b_w[7:4] < 4'd5) ? 4'd5 : b_w[7:4];
                            else if (is_tcp_now_w && (idx_w == (l4_off_w + 16'd13)))
                                tcp_flags_w      = b_w;
                        end

                        roce_now_w = (ethertype_w == ETYPE_ROCEV1) ||
                                     (saw_l3_w && (ip_proto_w == PROTO_UDP) &&
                                      ((src_port_w == PORT_ROCEV2) || (dst_port_w == PORT_ROCEV2)));
                        vxlan_now_w = saw_ipv4_w && (ip_proto_w == PROTO_UDP) &&
                                      (dst_port_w == PORT_VXLAN) && !roce_now_w;
                        vxlan_last_w = l4_off_w + 16'd15;
                        inner_et_w   = l4_off_w + 16'd29;

                        if (saw_l3_w && roce_now_w) begin
                            if (idx_w == bth_off_w)
                                bth_opcode_w = b_w;
                            else if (idx_w == (bth_off_w + 16'd2))
                                bth_pkey_w[15:8] = b_w;
                            else if (idx_w == (bth_off_w + 16'd3))
                                bth_pkey_w[7:0]  = b_w;
                            else if (idx_w == (bth_off_w + 16'd5))
                                dest_qp_w[23:16] = b_w;
                            else if (idx_w == (bth_off_w + 16'd6))
                                dest_qp_w[15:8]  = b_w;
                            else if (idx_w == (bth_off_w + 16'd7))
                                dest_qp_w[7:0]   = b_w;
                            else if (idx_w == (bth_off_w + 16'd8))
                                bth_ackreq_w     = b_w[7];
                            else if (idx_w == (bth_off_w + 16'd9))
                                bth_psn_w[23:16] = b_w;
                            else if (idx_w == (bth_off_w + 16'd10))
                                bth_psn_w[15:8]  = b_w;
                            else if (idx_w == (bth_off_w + 16'd11))
                                bth_psn_w[7:0]   = b_w;
                        end

                        if (saw_ipv4_w && vxlan_now_w) begin
                            if (idx_w == (l4_off_w + 16'd11))
                                vxlan_vni_w[23:16] = b_w;
                            else if (idx_w == (l4_off_w + 16'd12))
                                vxlan_vni_w[15:8] = b_w;
                            else if (idx_w == (l4_off_w + 16'd13))
                                vxlan_vni_w[7:0] = b_w;
                        end

                        if (!hdr_issued_w) begin
                            if (idx_w == 16'd13 && !saw_vlan_w && ethertype_w == ETYPE_ARP)
                                emit_w(1'b0, 1'b0, 1'b0, 1'b0, 1'b1, 1'b0);
                            else if (idx_w == 16'd13 && !saw_vlan_w && ethertype_w != ETYPE_IPV4 &&
                                     ethertype_w != ETYPE_IPV6)
                                emit_w(1'b0, 1'b0, 1'b1, 1'b0, 1'b0, 1'b0);
                            else if (idx_w == 16'd13 && last_b)
                                emit_w(1'b0, 1'b0, 1'b0, 1'b1, 1'b0, 1'b0);
                            else if (idx_w == 16'd17 && saw_vlan_w && vlan_etype_w == ETYPE_ARP)
                                emit_w(1'b0, 1'b0, 1'b0, 1'b0, 1'b1, 1'b0);
                            else if (idx_w == 16'd17 && saw_vlan_w && vlan_etype_w != ETYPE_IPV4 &&
                                     vlan_etype_w != ETYPE_IPV6)
                                emit_w(1'b0, 1'b0, 1'b1, 1'b0, 1'b0, 1'b0);
                            else if (idx_w == 16'd17 && saw_vlan_w && last_b)
                                emit_w(1'b0, 1'b0, 1'b0, 1'b1, 1'b0, 1'b0);
                            else if (saw_ipv4_w && is_tcp_now_w && !roce_now_w && !vxlan_now_w && idx_w == tcp_last_w)
                                emit_w(1'b1, 1'b0, 1'b0, 1'b0, 1'b0, 1'b0);
                            else if (saw_ipv6_w && is_tcp_now_w && !roce_now_w && idx_w == tcp_last_w)
                                emit_w(1'b0, 1'b1, 1'b0, 1'b0, 1'b0, 1'b0);
                            else if (saw_ipv4_w && needs_ports_w && !is_tcp_now_w && !roce_now_w && !vxlan_now_w && idx_w == l4_last_w)
                                emit_w(1'b1, 1'b0, 1'b0, 1'b0, 1'b0, 1'b0);
                            else if (saw_ipv6_w && needs_ports_w && !is_tcp_now_w && !roce_now_w && idx_w == l4_last_w)
                                emit_w(1'b0, 1'b1, 1'b0, 1'b0, 1'b0, 1'b0);
                            else if (saw_ipv4_w && roce_now_w && idx_w == bth_last_w)
                                emit_w(1'b1, 1'b0, 1'b0, 1'b0, 1'b0, 1'b0);
                            else if (saw_ipv6_w && roce_now_w && idx_w == bth_last_w)
                                emit_w(1'b0, 1'b1, 1'b0, 1'b0, 1'b0, 1'b0);
                            else if (saw_ipv4_w && vxlan_now_w && idx_w == inner_et_w)
                                emit_w(1'b1, 1'b0, 1'b0, 1'b0, 1'b0, 1'b1);
                            else if (saw_ipv4_w && !needs_ports_w && idx_w == (l3_w + 16'd19))
                                emit_w(1'b1, 1'b0, 1'b0, 1'b0, 1'b0, 1'b0);
                            else if (saw_ipv6_w && !needs_ports_w && idx_w == (l3_w + 16'd39))
                                emit_w(1'b0, 1'b1, 1'b0, 1'b0, 1'b0, 1'b0);
                            else if (last_b && idx_w < 16'd13)
                                emit_w(1'b0, 1'b0, 1'b0, 1'b1, 1'b0, 1'b0);
                            else if (last_b && saw_vlan_w && idx_w < 16'd17)
                                emit_w(1'b0, 1'b0, 1'b0, 1'b1, 1'b0, 1'b0);
                            else if (last_b && saw_ipv4_w && roce_now_w && idx_w < bth_last_w)
                                emit_w(1'b0, 1'b0, 1'b0, 1'b1, 1'b0, 1'b0);
                            else if (last_b && saw_ipv6_w && roce_now_w && idx_w < bth_last_w)
                                emit_w(1'b0, 1'b0, 1'b0, 1'b1, 1'b0, 1'b0);
                            else if (last_b && saw_ipv4_w && vxlan_now_w && idx_w < inner_et_w)
                                emit_w(1'b0, 1'b0, 1'b0, 1'b1, 1'b0, 1'b0);
                            else if (last_b && saw_ipv4_w && is_tcp_now_w && !roce_now_w && !vxlan_now_w && idx_w < tcp_last_w)
                                emit_w(1'b0, 1'b0, 1'b0, 1'b1, 1'b0, 1'b0);
                            else if (last_b && saw_ipv6_w && is_tcp_now_w && !roce_now_w && idx_w < tcp_last_w)
                                emit_w(1'b0, 1'b0, 1'b0, 1'b1, 1'b0, 1'b0);
                            else if (last_b && saw_ipv4_w && needs_ports_w && !is_tcp_now_w && !roce_now_w && !vxlan_now_w && idx_w < l4_last_w)
                                emit_w(1'b0, 1'b0, 1'b0, 1'b1, 1'b0, 1'b0);
                            else if (last_b && saw_ipv6_w && needs_ports_w && !is_tcp_now_w && !roce_now_w && idx_w < l4_last_w)
                                emit_w(1'b0, 1'b0, 1'b0, 1'b1, 1'b0, 1'b0);
                            else if (last_b && saw_ipv4_w && !needs_ports_w && idx_w < (l3_w + 16'd19))
                                emit_w(1'b0, 1'b0, 1'b0, 1'b1, 1'b0, 1'b0);
                            else if (last_b && saw_ipv6_w && !needs_ports_w && idx_w < (l3_w + 16'd39))
                                emit_w(1'b0, 1'b0, 1'b0, 1'b1, 1'b0, 1'b0);
                        end

                        idx_w = idx_w + 16'd1;
                    end
                end

                if (tlast && (saw_ipv4_w || saw_ipv6_w) && (ip_tot_len_w != 16'd0) &&
                    (idx_w != (l3_w + ip_tot_len_w)))
                    is_len_mis_w = 1'b1;

                iph_w  = saw_ipv6_w ? 16'd40 : {10'd0, ip_ihl_w, 2'b00};
                tcph_w = {10'd0, tcp_doff_w, 2'b00};
                if (is_tcp_w && (ip_tot_len_w >= (iph_w + tcph_w)))
                    tcp_plen_w = ip_tot_len_w - iph_w - tcph_w;
                else
                    tcp_plen_w = 16'd0;

                byte_idx     <= idx_w;
                hdr_issued   <= hdr_issued_w;
                saw_ipv4     <= saw_ipv4_w;
                saw_ipv6     <= saw_ipv6_w;
                saw_vlan     <= saw_vlan_w;
                vlan_tci     <= vlan_tci_w;
                vlan_etype   <= vlan_etype_w;
                ip_ihl       <= ip_ihl_w;
                tcp_doff     <= tcp_doff_w;
                dst_mac      <= dst_mac_w;
                src_mac      <= src_mac_w;
                ethertype    <= ethertype_w;
                src_ip       <= src_ip_w;
                dst_ip       <= dst_ip_w;
                src_ip6      <= src_ip6_w;
                dst_ip6      <= dst_ip6_w;
                ip_ttl       <= ip_ttl_w;
                ip_tot_len   <= ip_tot_len_w;
                ip_proto     <= ip_proto_w;
                src_port     <= src_port_w;
                dst_port     <= dst_port_w;
                tcp_seq      <= tcp_seq_w;
                tcp_ack      <= tcp_ack_w;
                tcp_flags    <= tcp_flags_w;
                tcp_plen     <= tcp_plen_w;
                bth_opcode   <= bth_opcode_w;
                bth_pkey     <= bth_pkey_w;
                bth_ackreq   <= bth_ackreq_w;
                dest_qp      <= dest_qp_w;
                bth_psn      <= bth_psn_w;
                hdr_valid    <= hdr_valid_w;
                is_ipv4      <= is_ipv4_w;
                is_ipv6      <= is_ipv6_w;
                is_vlan      <= saw_vlan_w;
                vlan_id      <= vlan_tci_w[11:0];
                is_non_ipv4  <= is_non_ipv4_w;
                is_truncated <= is_truncated_w;
                is_tcp       <= is_tcp_w;
                is_udp       <= is_udp_w;
                is_roce      <= is_roce_w;
                is_arp       <= is_arp_w;
                is_vxlan     <= is_vxlan_w;
                vxlan_vni    <= vxlan_vni_w;
                is_len_mismatch <= is_len_mis_w;
            end
        end
    end

    task automatic emit_w(
        input logic ipv4,
        input logic ipv6,
        input logic non_ipv4,
        input logic trunc,
        input logic arp,
        input logic vxlan
    );
        hdr_valid_w    = 1'b1;
        hdr_issued_w   = 1'b1;
        is_ipv4_w      = ipv4 && !arp;
        is_ipv6_w      = ipv6;
        is_non_ipv4_w  = non_ipv4;
        is_truncated_w = trunc;
        is_arp_w       = arp;
        is_vxlan_w     = vxlan;
        is_tcp_w       = (ipv4 || ipv6) && (ip_proto_w == PROTO_TCP) && !vxlan;
        is_udp_w       = (ipv4 || ipv6) && (ip_proto_w == PROTO_UDP) && !roce_now_w && !vxlan;
        is_roce_w      = roce_now_w && !vxlan;
    endtask

endmodule
