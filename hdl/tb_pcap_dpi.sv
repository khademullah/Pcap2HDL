`timescale 1ns/1ps

module tb_pcap_dpi #(
    parameter int DATA_W = 8
);

    localparam int KEEP_W = DATA_W / 8;

    import "DPI-C" function int open_pcap(input string filename);
    import "DPI-C" function int fetch_next_packet();
    import "DPI-C" function int get_wire_len();
    import "DPI-C" function longint get_ts_sec();
    import "DPI-C" function int get_ts_usec();
    import "DPI-C" function int get_datalink();
    import "DPI-C" function byte get_packet_byte();
    import "DPI-C" function void close_pcap();
    import "DPI-C" function int set_pcap_filter(input string filter);
    import "DPI-C" function int get_bpf_match();
    import "DPI-C" function int get_bpf_skip();
    import "DPI-C" function int open_pcap_dump(input string filename, input int linktype);
    import "DPI-C" function void dump_put_byte(input byte b);
    import "DPI-C" function int dump_packet(input longint ts_sec, input int ts_usec, input int wire_len);
    import "DPI-C" function int dump_pkt_count();
    import "DPI-C" function void close_pcap_dump();
    import "DPI-C" function int get_rss_valid();
    import "DPI-C" function int unsigned get_rss_hash();
    import "DPI-C" function int get_ip_csum_valid();
    import "DPI-C" function int get_ip_csum_ok();
    import "DPI-C" function int unsigned get_ip_csum();

    reg clk;
    reg rst_n;
    reg [DATA_W-1:0]   tdata;
    reg [KEEP_W-1:0]   tkeep;
    reg                tvalid;
    reg                bp_ready;
    wire               nic_tready;
    wire               tready;
    reg                tstart;
    reg                tlast;
    reg [31:0]         tuser;
    reg                tuser_err;

    wire        pkt_done;
    wire [31:0] pkt_bytes;
    wire        is_runt;
    wire        is_standard;
    wire        is_jumbo;

    wire        hdr_valid;
    wire        hdr_is_ipv4;
    wire        hdr_is_ipv6;
    wire        hdr_is_vlan;
    wire [11:0] vlan_id;
    wire        hdr_is_non_ipv4;
    wire        hdr_is_truncated;
    wire        hdr_is_tcp;
    wire        hdr_is_udp;
    wire        hdr_is_roce;
    wire        hdr_is_arp;
    wire        hdr_is_vxlan;
    wire [23:0] vxlan_vni;
    wire [47:0] dst_mac;
    wire [47:0] src_mac;
    wire [15:0] ethertype;
    wire [31:0] src_ip;
    wire [31:0] dst_ip;
    wire [127:0] src_ip6;
    wire [127:0] dst_ip6;
    wire [7:0]  ip_ttl;
    wire [15:0] ip_tot_len;
    wire        is_len_mismatch;
    wire [7:0]  ip_proto;
    wire [15:0] src_port;
    wire [15:0] dst_port;
    wire [31:0] tcp_seq;
    wire [31:0] tcp_ackn;
    wire [7:0]  tcp_flags;
    wire [15:0] tcp_plen;
    wire [7:0]  bth_opcode;
    wire [15:0] bth_pkey;
    wire        bth_ackreq;
    wire [23:0] dest_qp;
    wire [23:0] bth_psn;

    wire trk_evt;
    wire trk_psn_err;
    wire trk_op_err;
    wire trk_sess_full;
    wire trk_msg_done;
    wire trk_ack_ok;
    wire trk_psn_gap;

    wire tcp_evt;
    wire tcp_syn_ok;
    wire tcp_synack_ok;
    wire tcp_hs_done;
    wire tcp_fin_ok;
    wire tcp_rst_ok;
    wire tcp_seq_ok;
    wire tcp_seq_err;
    wire tcp_op_err;
    wire tcp_sess_full;

    wire        rss_valid;
    wire        rss_skip;
    wire [31:0] rss_hash;
    wire [1:0]  rss_qid;

    wire        icrc_valid;
    wire [31:0] icrc;
    wire        icrc_ok;
    wire        icrc_err;
    wire        icrc_skip;

    wire        csum_valid;
    wire        csum_ok;
    wire        csum_err;
    wire        csum_skip;
    wire [15:0] csum;

    wire        nic_pkt_valid;
    wire [31:0] nic_bytes;
    wire [31:0] nic_hash;
    wire        nic_err;
    wire        nic_drop;
    wire [15:0] nic_occ;
    wire        nic_irq;
    wire [31:0] axis_pkt_count;
    wire [31:0] axis_beat_count;
    wire [31:0] irq_pulse_count;

    wire [7:0]  axil_awaddr;
    wire        axil_awvalid;
    wire        axil_awready;
    wire [31:0] axil_wdata;
    wire [3:0]  axil_wstrb;
    wire        axil_wvalid;
    wire        axil_wready;
    wire [1:0]  axil_bresp;
    wire        axil_bvalid;
    wire        axil_bready;
    wire [7:0]  axil_araddr;
    wire        axil_arvalid;
    wire        axil_arready;
    wire [31:0] axil_rdata;
    wire [1:0]  axil_rresp;
    wire        axil_rvalid;
    wire        axil_rready;

    int pkt_len;
    int pkt_wire;
    int dlt;
    longint ts_sec;
    int ts_usec;
    int i;
    int k;
    int packet_count;
    int max_packets;
    int n_runt, n_standard, n_jumbo;
    int n_ipv4, n_ipv6, n_vlan, n_non_ipv4, n_truncated;
    int n_tcp, n_udp, n_roce;
    int n_msg, n_ack, n_psn_err, n_op_err;
    int n_hs, n_tcp_seq_ok, n_tcp_seq_err, n_tcp_op_err;
    int n_len_mis, n_fin, n_rst, n_psn_gap;
    int n_icrc_ok, n_icrc_err, n_icrc_skip;
    int n_rss_q0, n_rss_q1, n_rss_q2, n_rss_q3, n_rss_mis, n_rss_skip;
    int n_arp, n_vxlan;
    int n_csum_ok, n_csum_err, n_csum_skip, n_csum_mis;
    int n_nic, n_nic_drop, n_nic_byte_mis, n_nic_err;
    int n_axis_mis, n_csr_mis, n_irq_mis;
    logic        csr_req;
    logic        csr_req_write;
    logic [7:0]  csr_req_addr;
    logic [31:0] csr_req_wdata;
    logic        csr_done;
    logic [31:0] csr_rsp_rdata;
    logic [1:0]  csr_rsp_resp;
    int nic_pause_arg;
    int nic_occ_max;
    int n_cov_syn, n_cov_ack, n_cov_fin, n_cov_rst;
    int n_cov_op_send, n_cov_op_ack;
    int unsigned c_rss_hash;
    bit          c_rss_ok;
    bit          c_csum_ok;
    bit          c_csum_have;
    int unsigned c_csum;
    bit pace;
    int bp_arg;
    int pace_max_us;
    int idle_cyc;
    longint prev_ts_sec;
    int prev_ts_usec;
    longint delta_us;
    int pace_arg;
    string pcap_name;
    string pcap_arg;
    string dump_name;
    string dump_arg;
    string filter_arg;
    bit dumping;

    function automatic string bth_opname(input logic [7:0] op);
        case (op)
            8'h00: bth_opname = "SEND_FIRST";
            8'h01: bth_opname = "SEND_MIDDLE";
            8'h02: bth_opname = "SEND_LAST";
            8'h03: bth_opname = "SEND_LAST_IMM";
            8'h04: bth_opname = "SEND_ONLY";
            8'h05: bth_opname = "SEND_ONLY_IMM";
            8'h06: bth_opname = "WRITE_FIRST";
            8'h07: bth_opname = "WRITE_MIDDLE";
            8'h08: bth_opname = "WRITE_LAST";
            8'h0A: bth_opname = "WRITE_ONLY";
            8'h0C: bth_opname = "READ_REQ";
            8'h11: bth_opname = "ACK";
            default: bth_opname = $sformatf("OP_0x%02h", op);
        endcase
    endfunction

    function automatic string vlan_s();
        if (hdr_is_vlan)
            vlan_s = $sformatf("VLAN vid=%0d  ", vlan_id);
        else
            vlan_s = "";
    endfunction

    function automatic string tcp_flagstr(input logic [7:0] f);
        tcp_flagstr = "";
        if (f[0]) tcp_flagstr = {tcp_flagstr, "FIN "};
        if (f[1]) tcp_flagstr = {tcp_flagstr, "SYN "};
        if (f[2]) tcp_flagstr = {tcp_flagstr, "RST "};
        if (f[3]) tcp_flagstr = {tcp_flagstr, "PSH "};
        if (f[4]) tcp_flagstr = {tcp_flagstr, "ACK "};
        if (f[5]) tcp_flagstr = {tcp_flagstr, "URG "};
        if (tcp_flagstr.len() == 0)
            tcp_flagstr = "-";
        else
            tcp_flagstr = tcp_flagstr.substr(0, tcp_flagstr.len() - 2);
    endfunction

    pkt_snoop #(
        .DATA_W(DATA_W)
    ) u_snoop (
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
        .is_jumbo(is_jumbo),
        .hdr_valid(hdr_valid),
        .hdr_is_ipv4(hdr_is_ipv4),
        .hdr_is_ipv6(hdr_is_ipv6),
        .hdr_is_vlan(hdr_is_vlan),
        .vlan_id(vlan_id),
        .hdr_is_non_ipv4(hdr_is_non_ipv4),
        .hdr_is_truncated(hdr_is_truncated),
        .hdr_is_tcp(hdr_is_tcp),
        .hdr_is_udp(hdr_is_udp),
        .hdr_is_roce(hdr_is_roce),
        .hdr_is_arp(hdr_is_arp),
        .hdr_is_vxlan(hdr_is_vxlan),
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
        .tcp_ackn(tcp_ackn),
        .tcp_flags(tcp_flags),
        .tcp_plen(tcp_plen),
        .bth_opcode(bth_opcode),
        .bth_pkey(bth_pkey),
        .bth_ackreq(bth_ackreq),
        .dest_qp(dest_qp),
        .bth_psn(bth_psn),
        .trk_evt(trk_evt),
        .trk_psn_err(trk_psn_err),
        .trk_op_err(trk_op_err),
        .trk_sess_full(trk_sess_full),
        .trk_msg_done(trk_msg_done),
        .trk_ack_ok(trk_ack_ok),
        .trk_psn_gap(trk_psn_gap),
        .tcp_evt(tcp_evt),
        .tcp_syn_ok(tcp_syn_ok),
        .tcp_synack_ok(tcp_synack_ok),
        .tcp_hs_done(tcp_hs_done),
        .tcp_fin_ok(tcp_fin_ok),
        .tcp_rst_ok(tcp_rst_ok),
        .tcp_seq_ok(tcp_seq_ok),
        .tcp_seq_err(tcp_seq_err),
        .tcp_op_err(tcp_op_err),
        .tcp_sess_full(tcp_sess_full),
        .rss_valid(rss_valid),
        .rss_skip(rss_skip),
        .rss_hash(rss_hash),
        .rss_qid(rss_qid),
        .icrc_valid(icrc_valid),
        .icrc(icrc),
        .icrc_ok(icrc_ok),
        .icrc_err(icrc_err),
        .icrc_skip(icrc_skip),
        .csum_valid(csum_valid),
        .csum_ok(csum_ok),
        .csum_err(csum_err),
        .csum_skip(csum_skip),
        .csum(csum)
    );

`ifdef EN_NIC
    nic_rx #(
        .DATA_W(DATA_W),
        .DEPTH(16)
    ) u_nic_rx (
        .clk(clk),
        .rst_n(rst_n),
        .s_tdata(tdata),
        .s_tkeep(tkeep),
        .s_tvalid(tvalid),
        .s_tready(nic_tready),
        .s_tstart(tstart),
        .s_tlast(tlast),
        .s_tuser(tuser),
        .s_tuser_err(tuser_err),
        .ready_mask(bp_ready),
        .pause_en(nic_pause_arg != 0),
        .s_axil_awaddr(axil_awaddr),
        .s_axil_awvalid(axil_awvalid),
        .s_axil_awready(axil_awready),
        .s_axil_wdata(axil_wdata),
        .s_axil_wstrb(axil_wstrb),
        .s_axil_wvalid(axil_wvalid),
        .s_axil_wready(axil_wready),
        .s_axil_bresp(axil_bresp),
        .s_axil_bvalid(axil_bvalid),
        .s_axil_bready(axil_bready),
        .s_axil_araddr(axil_araddr),
        .s_axil_arvalid(axil_arvalid),
        .s_axil_arready(axil_arready),
        .s_axil_rdata(axil_rdata),
        .s_axil_rresp(axil_rresp),
        .s_axil_rvalid(axil_rvalid),
        .s_axil_rready(axil_rready),
        .irq_rx(nic_irq),
        .rx_pkt_valid(nic_pkt_valid),
        .rx_bytes(nic_bytes),
        .rx_hash(nic_hash),
        .rx_err(nic_err),
        .rx_drop(nic_drop),
        .rx_occ(nic_occ)
    );
    assign tready = nic_tready;
`else
    assign nic_tready    = bp_ready;
    assign tready        = bp_ready;
    assign nic_pkt_valid = 1'b0;
    assign nic_bytes     = 32'd0;
    assign nic_hash      = 32'd0;
    assign nic_err       = 1'b0;
    assign nic_drop      = 1'b0;
    assign nic_occ       = 16'd0;
    assign nic_irq       = 1'b0;
    assign axil_awready  = 1'b0;
    assign axil_wready   = 1'b0;
    assign axil_bresp    = 2'b00;
    assign axil_bvalid   = 1'b0;
    assign axil_arready  = 1'b0;
    assign axil_rdata    = 32'd0;
    assign axil_rresp    = 2'b00;
    assign axil_rvalid   = 1'b0;
`endif

    tb_axis_monitor u_axis_mon (
        .clk(clk),
        .rst_n(rst_n),
        .tvalid(tvalid),
        .tready(tready),
        .tlast(tlast),
        .pkt_count(axis_pkt_count),
        .beat_count(axis_beat_count)
    );

`ifdef EN_NIC
    tb_csr_axil_m u_csr (
        .clk(clk),
        .rst_n(rst_n),
        .req(csr_req),
        .req_write(csr_req_write),
        .req_addr(csr_req_addr),
        .req_wdata(csr_req_wdata),
        .done(csr_done),
        .rsp_rdata(csr_rsp_rdata),
        .rsp_resp(csr_rsp_resp),
        .awaddr(axil_awaddr),
        .awvalid(axil_awvalid),
        .awready(axil_awready),
        .wdata(axil_wdata),
        .wstrb(axil_wstrb),
        .wvalid(axil_wvalid),
        .wready(axil_wready),
        .bresp(axil_bresp),
        .bvalid(axil_bvalid),
        .bready(axil_bready),
        .araddr(axil_araddr),
        .arvalid(axil_arvalid),
        .arready(axil_arready),
        .rdata(axil_rdata),
        .rresp(axil_rresp),
        .rvalid(axil_rvalid),
        .rready(axil_rready)
    );

    tb_irq_monitor u_irq_mon (
        .clk(clk),
        .rst_n(rst_n),
        .irq(nic_irq),
        .pulse_count(irq_pulse_count)
    );
`else
    assign axil_awaddr  = 8'd0;
    assign axil_awvalid = 1'b0;
    assign axil_wdata   = 32'd0;
    assign axil_wstrb   = 4'd0;
    assign axil_wvalid  = 1'b0;
    assign axil_bready  = 1'b0;
    assign axil_araddr  = 8'd0;
    assign axil_arvalid = 1'b0;
    assign axil_rready  = 1'b0;
    assign irq_pulse_count = 32'd0;
    assign csr_done = 1'b0;
    assign csr_rsp_rdata = 32'd0;
    assign csr_rsp_resp  = 2'b00;
`endif

`ifdef EN_NIC
    task automatic csr_do_write(input logic [7:0] addr, input logic [31:0] data);
        begin
            csr_req_write = 1'b1;
            csr_req_addr  = addr;
            csr_req_wdata = data;
            @(negedge clk);
            csr_req = 1'b1;
            @(posedge clk);
            @(negedge clk);
            csr_req = 1'b0;
            while (!csr_done)
                @(posedge clk);
        end
    endtask

    task automatic csr_do_read(input logic [7:0] addr);
        begin
            csr_req_write = 1'b0;
            csr_req_addr  = addr;
            @(negedge clk);
            csr_req = 1'b1;
            @(posedge clk);
            @(negedge clk);
            csr_req = 1'b0;
            while (!csr_done)
                @(posedge clk);
        end
    endtask
`endif

    always #5 clk = ~clk;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            bp_ready <= 1'b1;
        else if (bp_arg == 1)
            bp_ready <= ~bp_ready;
        else if (bp_arg == 2)
            bp_ready <= 1'($urandom_range(0, 1));
        else
            bp_ready <= 1'b1;
    end

    always @(posedge clk) begin
        if (rst_n && pkt_done) begin
            if (is_jumbo)
                n_jumbo = n_jumbo + 1;
            else if (is_runt)
                n_runt = n_runt + 1;
            else
                n_standard = n_standard + 1;

            $display("[DUT] Classified packet: %0d bytes -> %s",
                     pkt_bytes,
                     is_jumbo    ? "JUMBO" :
                     is_runt     ? "RUNT"  :
                                   "STANDARD");
        end
    end

`ifdef EN_NIC
    always @(posedge clk) begin
        if (rst_n && (32'(nic_occ) > nic_occ_max))
            nic_occ_max = 32'(nic_occ);
        if (rst_n && nic_drop)
            n_nic_drop = n_nic_drop + 1;
        if (rst_n && nic_pkt_valid) begin
            n_nic = n_nic + 1;
            if (nic_err)
                n_nic_err = n_nic_err + 1;
            if (!pkt_done || (nic_bytes != pkt_bytes))
                n_nic_byte_mis = n_nic_byte_mis + 1;
        end
    end
`endif

    always @(posedge clk) begin
        if (rst_n && is_len_mismatch) begin
            n_len_mis = n_len_mis + 1;
            $display("[DUT] LEN_MISMATCH  captured=%0d  expected=%0d (%0d+iplen)",
                     pkt_bytes, (hdr_is_vlan ? 16'd18 : 16'd14) + ip_tot_len,
                     hdr_is_vlan ? 18 : 14);
        end
    end

    always @(posedge clk) begin
        if (rst_n && icrc_valid) begin
            if (icrc_ok)   n_icrc_ok   = n_icrc_ok + 1;
            if (icrc_err)  n_icrc_err  = n_icrc_err + 1;
            if (icrc_skip) n_icrc_skip = n_icrc_skip + 1;
            if (icrc_skip)
                $display("[DUT] ICRC  %08h SKIP (truncated)", icrc);
            else if (icrc_ok)
                $display("[DUT] ICRC  %08h OK", icrc);
            else
                $display("[DUT] ICRC  %08h BAD", icrc);
        end
    end

    always @(posedge clk) begin
        if (rst_n && csum_valid) begin
            if (csum_ok)   n_csum_ok   = n_csum_ok + 1;
            if (csum_err)  n_csum_err  = n_csum_err + 1;
            if (csum_skip) n_csum_skip = n_csum_skip + 1;
            if (csum_ok || csum_err) begin
                if (!c_csum_have || (csum_ok != c_csum_ok) || (csum != c_csum[15:0])) begin
                    n_csum_mis = n_csum_mis + 1;
                    $display("[CSUM] %04h DPI=%04h MISMATCH", csum, c_csum[15:0]);
                end else if (csum_ok)
                    $display("[CSUM] %04h OK", csum);
                else
                    $display("[CSUM] %04h BAD", csum);
            end
        end
    end

    always @(posedge clk) begin
        if (rst_n && rss_skip)
            n_rss_skip = n_rss_skip + 1;
        if (rst_n && rss_valid) begin
            unique case (rss_qid)
                2'd0: n_rss_q0 = n_rss_q0 + 1;
                2'd1: n_rss_q1 = n_rss_q1 + 1;
                2'd2: n_rss_q2 = n_rss_q2 + 1;
                default: n_rss_q3 = n_rss_q3 + 1;
            endcase
            if (!c_rss_ok || (rss_hash != c_rss_hash)) begin
                n_rss_mis = n_rss_mis + 1;
                $display("[RSS] q=%0d hash=%08h DPI=%08h MISMATCH",
                         rss_qid, rss_hash, c_rss_hash);
            end else
                $display("[RSS] q=%0d hash=%08h", rss_qid, rss_hash);
        end
    end

    always @(posedge clk) begin
        if (rst_n && hdr_valid) begin
            if (hdr_is_truncated)
                n_truncated = n_truncated + 1;
            else if (hdr_is_arp)
                ;
            else if (hdr_is_ipv4)
                n_ipv4 = n_ipv4 + 1;
            else if (hdr_is_ipv6)
                n_ipv6 = n_ipv6 + 1;
            else
                n_non_ipv4 = n_non_ipv4 + 1;
            if (hdr_is_vlan)
                n_vlan = n_vlan + 1;
            if (hdr_is_tcp)  n_tcp  = n_tcp + 1;
            if (hdr_is_udp)  n_udp  = n_udp + 1;
            if (hdr_is_roce) n_roce = n_roce + 1;
            if (hdr_is_arp)  n_arp  = n_arp + 1;
            if (hdr_is_vxlan) n_vxlan = n_vxlan + 1;
            if (hdr_is_tcp) begin
                if (tcp_flags[1]) n_cov_syn = n_cov_syn + 1;
                if (tcp_flags[4]) n_cov_ack = n_cov_ack + 1;
                if (tcp_flags[0]) n_cov_fin = n_cov_fin + 1;
                if (tcp_flags[2]) n_cov_rst = n_cov_rst + 1;
            end
            if (hdr_is_roce) begin
                if (bth_opcode == 8'h00 || bth_opcode == 8'h01 || bth_opcode == 8'h02)
                    n_cov_op_send = n_cov_op_send + 1;
                if (bth_opcode == 8'h11)
                    n_cov_op_ack = n_cov_op_ack + 1;
            end

            if (hdr_is_arp)
                $display("[HDR] dst=%012h  src=%012h  etype=0x%04h  %sARP",
                         dst_mac, src_mac, ethertype, vlan_s());
            else if (hdr_is_vxlan)
                $display("[HDR] dst=%012h  src=%012h  etype=0x%04h  %sIPv4 ttl=%0d iplen=%0d  %0d.%0d.%0d.%0d:%0d -> %0d.%0d.%0d.%0d:%0d  VXLAN vni=%0d",
                         dst_mac, src_mac, ethertype, vlan_s(), ip_ttl, ip_tot_len,
                         src_ip[31:24], src_ip[23:16], src_ip[15:8], src_ip[7:0], src_port,
                         dst_ip[31:24], dst_ip[23:16], dst_ip[15:8], dst_ip[7:0], dst_port,
                         vxlan_vni);
            else if (hdr_is_roce) begin
                if (bth_ackreq)
                    $display("[HDR] dst=%012h  src=%012h  etype=0x%04h  %sIPv4 ttl=%0d iplen=%0d  %0d.%0d.%0d.%0d:%0d -> %0d.%0d.%0d.%0d:%0d  ROCE %s qp=0x%0h psn=0x%0h pkey=0x%04h AckReq",
                             dst_mac, src_mac, ethertype, vlan_s(), ip_ttl, ip_tot_len,
                             src_ip[31:24], src_ip[23:16], src_ip[15:8], src_ip[7:0], src_port,
                             dst_ip[31:24], dst_ip[23:16], dst_ip[15:8], dst_ip[7:0], dst_port,
                             bth_opname(bth_opcode), dest_qp, bth_psn, bth_pkey);
                else
                    $display("[HDR] dst=%012h  src=%012h  etype=0x%04h  %sIPv4 ttl=%0d iplen=%0d  %0d.%0d.%0d.%0d:%0d -> %0d.%0d.%0d.%0d:%0d  ROCE %s qp=0x%0h psn=0x%0h pkey=0x%04h",
                             dst_mac, src_mac, ethertype, vlan_s(), ip_ttl, ip_tot_len,
                             src_ip[31:24], src_ip[23:16], src_ip[15:8], src_ip[7:0], src_port,
                             dst_ip[31:24], dst_ip[23:16], dst_ip[15:8], dst_ip[7:0], dst_port,
                             bth_opname(bth_opcode), dest_qp, bth_psn, bth_pkey);
            end else if (hdr_is_ipv6)
                $display("[HDR] dst=%012h  src=%012h  etype=0x%04h      %sIPv6 hop=%0d iplen=%0d  %032h:%0d -> %032h:%0d  %s",
                         dst_mac, src_mac, ethertype, vlan_s(), ip_ttl, ip_tot_len,
                         src_ip6, src_port, dst_ip6, dst_port,
                         hdr_is_tcp ? $sformatf("TCP %s seq=0x%08h ack=0x%08h plen=%0d",
                                                tcp_flagstr(tcp_flags), tcp_seq, tcp_ackn, tcp_plen) :
                         hdr_is_udp ? "UDP" : "");
            else
                $display("[HDR] dst=%012h  src=%012h  etype=0x%04h  %s%s ttl=%0d iplen=%0d  %0d.%0d.%0d.%0d:%0d -> %0d.%0d.%0d.%0d:%0d  %s",
                         dst_mac, src_mac, ethertype, vlan_s(),
                         hdr_is_truncated ? "TRUNC" : hdr_is_ipv4 ? "IPv4" : "NON-IPv4",
                         ip_ttl, ip_tot_len,
                         src_ip[31:24], src_ip[23:16], src_ip[15:8], src_ip[7:0], src_port,
                         dst_ip[31:24], dst_ip[23:16], dst_ip[15:8], dst_ip[7:0], dst_port,
                         hdr_is_tcp ? $sformatf("TCP %s seq=0x%08h ack=0x%08h plen=%0d",
                                                tcp_flagstr(tcp_flags), tcp_seq, tcp_ackn, tcp_plen) :
                         hdr_is_udp ? "UDP" : "");
        end
    end

    always @(posedge clk) begin
        if (rst_n && trk_evt) begin
            if (trk_msg_done) n_msg     = n_msg + 1;
            if (trk_ack_ok)   n_ack     = n_ack + 1;
            if (trk_psn_err)  n_psn_err = n_psn_err + 1;
            if (trk_op_err)   n_op_err  = n_op_err + 1;
            if (trk_psn_gap)  n_psn_gap = n_psn_gap + 1;
            if (trk_sess_full)
                $display("[TRK] SESS_FULL");
            else if (trk_psn_err)
                $display("[TRK] PSN_ERR");
            else if (trk_op_err)
                $display("[TRK] OP_ERR");
            else if (trk_psn_gap)
                $display("[TRK] PSN_GAP");
            else if (trk_ack_ok)
                $display("[TRK] ACK_OK");
            else if (trk_msg_done)
                $display("[TRK] MSG_DONE");
            else
                $display("[TRK] OK");
        end
    end

    always @(posedge clk) begin
        if (rst_n && tcp_evt) begin
            if (tcp_hs_done)      n_hs          = n_hs + 1;
            if (tcp_fin_ok)       n_fin         = n_fin + 1;
            if (tcp_rst_ok)       n_rst         = n_rst + 1;
            if (tcp_seq_ok)       n_tcp_seq_ok  = n_tcp_seq_ok + 1;
            if (tcp_seq_err)      n_tcp_seq_err = n_tcp_seq_err + 1;
            if (tcp_op_err)       n_tcp_op_err  = n_tcp_op_err + 1;
            if (tcp_sess_full)
                $display("[TCP] SESS_FULL");
            else if (tcp_seq_err)
                $display("[TCP] SEQ_ERR");
            else if (tcp_op_err)
                $display("[TCP] OP_ERR");
            else if (tcp_rst_ok)
                $display("[TCP] RST");
            else if (tcp_fin_ok)
                $display("[TCP] FIN_OK");
            else if (tcp_hs_done)
                $display("[TCP] HS_DONE");
            else if (tcp_synack_ok)
                $display("[TCP] SYNACK_OK");
            else if (tcp_syn_ok)
                $display("[TCP] SYN_OK");
            else if (tcp_seq_ok)
                $display("[TCP] SEQ_OK");
            else
                $display("[TCP] OK");
        end
    end

    initial begin
        $dumpfile("simulation_trace.vcd");
        $dumpvars(0, tb_pcap_dpi);
    end

    initial begin
        clk = 0;
        rst_n = 0;
        tdata = '0;
        tkeep = '0;
        tvalid = 0;
        tstart = 0;
        tlast = 0;
        tuser = '0;
        tuser_err = 1'b0;
        packet_count = 0;
        n_runt = 0;
        n_standard = 0;
        n_jumbo = 0;
        n_ipv4 = 0;
        n_ipv6 = 0;
        n_vlan = 0;
        n_non_ipv4 = 0;
        n_truncated = 0;
        n_tcp = 0;
        n_udp = 0;
        n_roce = 0;
        n_msg = 0;
        n_ack = 0;
        n_psn_err = 0;
        n_op_err = 0;
        n_hs = 0;
        n_tcp_seq_ok = 0;
        n_tcp_seq_err = 0;
        n_tcp_op_err = 0;
        n_len_mis = 0;
        n_fin = 0;
        n_rst = 0;
        n_psn_gap = 0;
        n_icrc_ok = 0;
        n_icrc_err = 0;
        n_icrc_skip = 0;
        n_rss_q0 = 0;
        n_rss_q1 = 0;
        n_rss_q2 = 0;
        n_rss_q3 = 0;
        n_rss_mis = 0;
        n_rss_skip = 0;
        n_arp = 0;
        n_vxlan = 0;
        n_csum_ok = 0;
        n_csum_err = 0;
        n_csum_skip = 0;
        n_csum_mis = 0;
        n_nic = 0;
        n_nic_drop = 0;
        n_nic_byte_mis = 0;
        n_nic_err = 0;
        n_axis_mis = 0;
        n_csr_mis = 0;
        n_irq_mis = 0;
        csr_req = 1'b0;
        csr_req_write = 1'b0;
        csr_req_addr = 8'd0;
        csr_req_wdata = 32'd0;
        nic_pause_arg = 0;
        nic_occ_max = 0;
        n_cov_syn = 0;
        n_cov_ack = 0;
        n_cov_fin = 0;
        n_cov_rst = 0;
        n_cov_op_send = 0;
        n_cov_op_ack = 0;
        c_rss_hash = 0;
        c_rss_ok = 0;
        c_csum_ok = 0;
        c_csum_have = 0;
        c_csum = 0;
        max_packets = 100;
        pace_arg = 0;
        pace = 1'b0;
        bp_arg = 0;
        pace_max_us = 100;
        prev_ts_sec = 0;
        prev_ts_usec = 0;
        pcap_name = "traffic.pcap";
        dump_name = "";
        dumping = 1'b0;
        void'($value$plusargs("MAX_PACKETS=%d", max_packets));
        if ($value$plusargs("PCAP=%s", pcap_arg) && pcap_arg.len() != 0)
            pcap_name = pcap_arg;
        if ($value$plusargs("DUMP=%s", dump_arg) && dump_arg.len() != 0)
            dump_name = dump_arg;
        dumping = (dump_name.len() != 0);
        filter_arg = "";
        void'($value$plusargs("FILTER=%s", filter_arg));
        void'($value$plusargs("PACE=%d", pace_arg));
        void'($value$plusargs("PACE_MAX_US=%d", pace_max_us));
        void'($value$plusargs("BP=%d", bp_arg));
        void'($value$plusargs("NIC_PAUSE=%d", nic_pause_arg));
        pace = (pace_arg != 0);

        #20;
        rst_n = 1;
        #10;

`ifdef EN_NIC
        csr_do_write(8'h00, 32'h5);
        csr_do_read(8'h00);
        if (csr_rsp_rdata[2:0] != 3'b101)
            n_csr_mis = n_csr_mis + 1;
        if (csr_rsp_resp != 2'b00)
            n_csr_mis = n_csr_mis + 1;
        $display("[CSR] CTRL wr=0x5 rd=0x%0h", csr_rsp_rdata);
`endif

        $display("[SV] Opening %s", pcap_name);
        if (pcap_name.len() == 0 || open_pcap(pcap_name) != 0) begin
            $display("[SV] Failed to open PCAP file. Exiting.");
            $finish;
        end else begin

        dlt = get_datalink();
        $display("[SV] Datalink DLT=%0d%s", dlt, (dlt == 1) ? " (Ethernet)" : "");
        if (filter_arg.len() != 0) begin
            if (set_pcap_filter(filter_arg) != 0) begin
                $display("[SV] Failed to install BPF filter. Exiting.");
                close_pcap();
                $finish;
            end
        end
        if (dumping) begin
            if (open_pcap_dump(dump_name, dlt) != 0) begin
                $display("[SV] Failed to open dump %s. Exiting.", dump_name);
                close_pcap();
                $finish;
            end
        end
        if (DATA_W != 8)
            $display("[SV] AXIS DATA_W=%0d (%0d bytes/beat)", DATA_W, KEEP_W);
        $display("[SV] Streaming up to %0d packets%s%s%s%s",
                 max_packets,
                 pace ? $sformatf(" (PACE=1, IFG cap %0d us)", pace_max_us) : "",
                 (bp_arg == 1) ? " (BP=1, extra tready 50%)" :
                 (bp_arg == 2) ? " (BP=2, extra random tready)" : "",
                 (nic_pause_arg != 0) ? " NIC_PAUSE=1" : "",
                 (filter_arg.len() != 0) ? $sformatf(" FILTER=%s", filter_arg) : "");

        while (1) begin
            if (packet_count >= max_packets) begin
                $display("\n[SV] Reached packet cap of %0d. Stopping stream.", packet_count);
                break;
            end

            pkt_len = fetch_next_packet();
            if (pkt_len == 0) begin
                $display("\n[SV] Reached end of PCAP before hitting the packet cap.");
                break;
            end

            pkt_wire = get_wire_len();
            ts_sec   = get_ts_sec();
            ts_usec  = get_ts_usec();
            packet_count = packet_count + 1;
            c_rss_ok   = (get_rss_valid() != 0);
            c_rss_hash = get_rss_hash();
            c_csum_have = (get_ip_csum_valid() != 0);
            c_csum_ok   = (get_ip_csum_ok() != 0);
            c_csum      = get_ip_csum();
            $display("[SV] Processing Packet #%0d (captured %0d / wire %0d bytes) ts=%0d.%06d",
                     packet_count, pkt_len, pkt_wire, ts_sec, ts_usec);
            if (pkt_len < pkt_wire)
                $display("[SV] Capture truncated: %0d bytes missing from wire frame",
                         pkt_wire - pkt_len);

            if (pace && packet_count > 1) begin
                delta_us = (ts_sec - prev_ts_sec) * 64'sd1000000 +
                           (longint'(ts_usec) - longint'(prev_ts_usec));
                if (delta_us < 0)
                    delta_us = 0;
                if (delta_us > longint'(pace_max_us))
                    delta_us = longint'(pace_max_us);
                idle_cyc = int'(delta_us * 64'sd100);
                if (idle_cyc < 3)
                    idle_cyc = 3;
                $display("[SV] IFG %0d us -> %0d cycles", delta_us, idle_cyc);
                if (idle_cyc > 3)
                    repeat (idle_cyc - 3) @(posedge clk);
            end

            prev_ts_sec  = ts_sec;
            prev_ts_usec = ts_usec;

            for (i = 0; i < pkt_len; i = i + KEEP_W) begin
                @(negedge clk);
                tdata  = '0;
                tkeep  = '0;
                for (k = 0; k < KEEP_W; k = k + 1) begin
                    if ((i + k) < pkt_len) begin
                        tdata[8*k +: 8] = get_packet_byte();
                        tkeep[k]        = 1'b1;
                    end
                end
                tvalid = 1;
                tstart = (i == 0);
                tlast  = ((i + KEEP_W) >= pkt_len);
                tuser     = c_rss_ok ? c_rss_hash : 32'd0;
                tuser_err = c_csum_have && !c_csum_ok;
                do @(posedge clk); while (!tready);
                if (dumping) begin
                    for (k = 0; k < KEEP_W; k = k + 1)
                        if (tkeep[k])
                            dump_put_byte(tdata[8*k +: 8]);
                    if (tlast)
                        void'(dump_packet(ts_sec, ts_usec, pkt_wire));
                end
            end

            @(negedge clk);
            tvalid = 0;
            tstart = 0;
            tlast  = 0;
            tuser  = '0;
            tuser_err = 1'b0;
            tdata  = '0;
            tkeep  = '0;
            repeat (3) @(posedge clk);
        end

        close_pcap();
        if (dumping) begin
            $display("[SV] Wrote %0d packets to %s", dump_pkt_count(), dump_name);
            close_pcap_dump();
        end
        if (filter_arg.len() != 0)
            $display("[C-DPI] BPF matched=%0d skipped=%0d",
                     get_bpf_match(), get_bpf_skip());
        $display("\n[SV] Simulation finished. File=%s  Streamed %0d packets.", pcap_name, packet_count);
        $display("[DUT] Size    runt=%0d  standard=%0d  jumbo=%0d",
                 n_runt, n_standard, n_jumbo);
        $display("[DUT] Header  ipv4=%0d  ipv6=%0d  vlan=%0d  tcp=%0d  udp=%0d  roce=%0d  arp=%0d  vxlan=%0d  other=%0d  trunc=%0d",
                 n_ipv4, n_ipv6, n_vlan, n_tcp, n_udp, n_roce, n_arp, n_vxlan, n_non_ipv4, n_truncated);
        $display("[DUT] Tracker msg=%0d  ack=%0d  psn_err=%0d  op_err=%0d  psn_gap=%0d",
                 n_msg, n_ack, n_psn_err, n_op_err, n_psn_gap);
        $display("[DUT] TCP     hs=%0d  fin=%0d  rst=%0d  seq_ok=%0d  seq_err=%0d  op_err=%0d",
                 n_hs, n_fin, n_rst, n_tcp_seq_ok, n_tcp_seq_err, n_tcp_op_err);
        $display("[DUT] Length  mismatch=%0d", n_len_mis);
        $display("[DUT] ICRC    ok=%0d  err=%0d  skip=%0d",
                 n_icrc_ok, n_icrc_err, n_icrc_skip);
        $display("[DUT] CSUM     ok=%0d  err=%0d  skip=%0d  mis=%0d",
                 n_csum_ok, n_csum_err, n_csum_skip, n_csum_mis);
        $display("[DUT] RSS     q0=%0d  q1=%0d  q2=%0d  q3=%0d  mis=%0d  skip=%0d",
                 n_rss_q0, n_rss_q1, n_rss_q2, n_rss_q3, n_rss_mis, n_rss_skip);
`ifdef EN_NIC
        $display("[NIC] rx=%0d  drop=%0d  byte_mis=%0d  csum_side=%0d  occ_max=%0d  mis=%0d",
                 n_nic, n_nic_drop, n_nic_byte_mis, n_nic_err, nic_occ_max,
                 (n_nic != packet_count) || (n_nic_drop != 0) || (n_nic_byte_mis != 0));
        csr_do_read(8'h04);
        if (csr_rsp_rdata != 32'(n_nic))
            n_csr_mis = n_csr_mis + 1;
        if (irq_pulse_count != 32'(n_nic))
            n_irq_mis = n_irq_mis + 1;
        $display("[CSR] STATUS=%0d  mis=%0d", csr_rsp_rdata, n_csr_mis);
        $display("[IRQ] pulses=%0d  mis=%0d", irq_pulse_count, n_irq_mis);
`else
        $display("[NIC] off  (rebuild with make NIC=1)");
        $display("[CSR] off");
        $display("[IRQ] off");
`endif
        n_axis_mis = (axis_pkt_count != 32'(packet_count)) ? 1 : 0;
        $display("[AXIS] pkts=%0d  beats=%0d  mis=%0d",
                 axis_pkt_count, axis_beat_count, n_axis_mis);
        $display("[COV] size    runt=%0d  standard=%0d  jumbo=%0d  tcp SYN=%0d ACK=%0d FIN=%0d RST=%0d  roce send=%0d ack=%0d",
                 n_runt, n_standard, n_jumbo, n_cov_syn, n_cov_ack, n_cov_fin, n_cov_rst,
                 n_cov_op_send, n_cov_op_ack);
        $finish;
        end
    end

endmodule
