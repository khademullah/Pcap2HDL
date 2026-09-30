// Observer hierarchy: AXIS snoops + parser-metadata clients.
// Does not drive tready. Instantiated as u_snoop under tb_pcap_dpi.

`timescale 1ns/1ps

module pkt_snoop #(
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

    output logic        pkt_done,
    output logic [31:0] pkt_bytes,
    output logic        is_runt,
    output logic        is_standard,
    output logic        is_jumbo,

    output logic        hdr_valid,
    output logic        hdr_is_ipv4,
    output logic        hdr_is_ipv6,
    output logic        hdr_is_non_ipv4,
    output logic        hdr_is_truncated,
    output logic        hdr_is_tcp,
    output logic        hdr_is_udp,
    output logic        hdr_is_roce,
    output logic        hdr_is_arp,
    output logic        hdr_is_vxlan,
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
    output logic [31:0] tcp_ackn,
    output logic [7:0]  tcp_flags,
    output logic [15:0] tcp_plen,
    output logic [7:0]  bth_opcode,
    output logic [15:0] bth_pkey,
    output logic        bth_ackreq,
    output logic [23:0] dest_qp,
    output logic [23:0] bth_psn,

    output logic        trk_evt,
    output logic        trk_psn_err,
    output logic        trk_op_err,
    output logic        trk_sess_full,
    output logic        trk_msg_done,
    output logic        trk_ack_ok,
    output logic        trk_psn_gap,

    output logic        tcp_evt,
    output logic        tcp_syn_ok,
    output logic        tcp_synack_ok,
    output logic        tcp_hs_done,
    output logic        tcp_fin_ok,
    output logic        tcp_rst_ok,
    output logic        tcp_seq_ok,
    output logic        tcp_seq_err,
    output logic        tcp_op_err,
    output logic        tcp_sess_full,

    output logic        rss_valid,
    output logic        rss_skip,
    output logic [31:0] rss_hash,
    output logic [1:0]  rss_qid,

    output logic        icrc_valid,
    output logic [31:0] icrc,
    output logic        icrc_ok,
    output logic        icrc_err,
    output logic        icrc_skip,

    output logic        csum_valid,
    output logic        csum_ok,
    output logic        csum_err,
    output logic        csum_skip,
    output logic [15:0] csum
);

    pkt_size_filter #(
        .DATA_W(DATA_W),
        .JUMBO_THRESH(1500),
        .MIN_FRAME(64)
    ) u_filter (
        .clk(clk),
        .rst_n(rst_n),
        .tdata(tdata),
        .tkeep(tkeep),
        .tvalid(tvalid),
        .tready(tready),
        .tstart(tstart),
        .tlast(tlast),
        .pkt_done(pkt_done),
        .pkt_bytes(pkt_bytes),
        .is_runt(is_runt),
        .is_standard(is_standard),
        .is_jumbo(is_jumbo)
    );

    pkt_header_parser #(
        .DATA_W(DATA_W)
    ) u_parser (
        .clk(clk),
        .rst_n(rst_n),
        .tdata(tdata),
        .tkeep(tkeep),
        .tvalid(tvalid),
        .tready(tready),
        .tstart(tstart),
        .tlast(tlast),
        .hdr_valid(hdr_valid),
        .is_ipv4(hdr_is_ipv4),
        .is_ipv6(hdr_is_ipv6),
        .is_non_ipv4(hdr_is_non_ipv4),
        .is_truncated(hdr_is_truncated),
        .is_tcp(hdr_is_tcp),
        .is_udp(hdr_is_udp),
        .is_roce(hdr_is_roce),
        .is_arp(hdr_is_arp),
        .is_vxlan(hdr_is_vxlan),
        .vxlan_vni(vxlan_vni),
        .dst_mac(dst_mac),
        .src_mac(src_mac),
        .ethertype(ethertype),
        .src_ip(src_ip),
        .dst_ip(dst_ip),
        .src_ip6(src_ip6),
        .dst_ip6(dst_ip6),
        .ip_ttl(ip_ttl),
        .ip_tot_len(ip_tot_len),
        .is_len_mismatch(is_len_mismatch),
        .ip_proto(ip_proto),
        .src_port(src_port),
        .dst_port(dst_port),
        .tcp_seq(tcp_seq),
        .tcp_ack(tcp_ackn),
        .tcp_flags(tcp_flags),
        .tcp_plen(tcp_plen),
        .bth_opcode(bth_opcode),
        .bth_pkey(bth_pkey),
        .bth_ackreq(bth_ackreq),
        .dest_qp(dest_qp),
        .bth_psn(bth_psn)
    );

    pkt_roce_tracker #(
        .NUM_SESS(4)
    ) u_tracker (
        .clk(clk),
        .rst_n(rst_n),
        .hdr_valid(hdr_valid),
        .is_roce(hdr_is_roce),
        .src_ip(src_ip),
        .dst_ip(dst_ip),
        .opcode(bth_opcode),
        .dest_qp(dest_qp),
        .psn(bth_psn),
        .evt_valid(trk_evt),
        .psn_err(trk_psn_err),
        .op_err(trk_op_err),
        .sess_full(trk_sess_full),
        .msg_done(trk_msg_done),
        .ack_ok(trk_ack_ok),
        .psn_gap(trk_psn_gap)
    );

    pkt_tcp_tracker #(
        .NUM_SESS(4)
    ) u_tcp (
        .clk(clk),
        .rst_n(rst_n),
        .hdr_valid(hdr_valid),
        .is_tcp(hdr_is_tcp),
        .src_ip(src_ip6),
        .dst_ip(dst_ip6),
        .src_port(src_port),
        .dst_port(dst_port),
        .seq(tcp_seq),
        .ack(tcp_ackn),
        .flags(tcp_flags),
        .plen(tcp_plen),
        .evt_valid(tcp_evt),
        .syn_ok(tcp_syn_ok),
        .synack_ok(tcp_synack_ok),
        .hs_done(tcp_hs_done),
        .fin_ok(tcp_fin_ok),
        .rst_ok(tcp_rst_ok),
        .seq_ok(tcp_seq_ok),
        .seq_err(tcp_seq_err),
        .op_err(tcp_op_err),
        .sess_full(tcp_sess_full)
    );

    pkt_roce_icrc #(
        .DATA_W(DATA_W)
    ) u_icrc (
        .clk(clk),
        .rst_n(rst_n),
        .tdata(tdata),
        .tkeep(tkeep),
        .tvalid(tvalid),
        .tready(tready),
        .tstart(tstart),
        .tlast(tlast),
        .is_roce(hdr_is_roce),
        .ip_tot_len(ip_tot_len),
        .icrc_valid(icrc_valid),
        .icrc(icrc),
        .icrc_ok(icrc_ok),
        .icrc_err(icrc_err),
        .icrc_skip(icrc_skip)
    );

    pkt_rss #(
        .NUM_Q(4)
    ) u_rss (
        .clk(clk),
        .rst_n(rst_n),
        .hdr_valid(hdr_valid),
        .is_ipv4(hdr_is_ipv4),
        .is_ipv6(hdr_is_ipv6),
        .is_truncated(hdr_is_truncated),
        .ip_proto(ip_proto),
        .src_ip(src_ip),
        .dst_ip(dst_ip),
        .src_ip6(src_ip6),
        .dst_ip6(dst_ip6),
        .src_port(src_port),
        .dst_port(dst_port),
        .rss_valid(rss_valid),
        .rss_skip(rss_skip),
        .rss_hash(rss_hash),
        .rss_qid(rss_qid)
    );

    pkt_ip_csum #(
        .DATA_W(DATA_W)
    ) u_csum (
        .clk(clk),
        .rst_n(rst_n),
        .tdata(tdata),
        .tkeep(tkeep),
        .tvalid(tvalid),
        .tready(tready),
        .tstart(tstart),
        .tlast(tlast),
        .csum_valid(csum_valid),
        .csum_ok(csum_ok),
        .csum_err(csum_err),
        .csum_skip(csum_skip),
        .csum(csum)
    );

endmodule
