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

    reg clk;
    reg rst_n;
    reg [DATA_W-1:0]   tdata;
    reg [KEEP_W-1:0]   tkeep;
    reg                tvalid;
    reg                tready;
    reg                tstart;
    reg                tlast;

    wire        pkt_done;
    wire [31:0] pkt_bytes;
    wire        is_runt;
    wire        is_standard;
    wire        is_jumbo;

    wire        hdr_valid;
    wire        hdr_is_ipv4;
    wire        hdr_is_non_ipv4;
    wire        hdr_is_truncated;
    wire        hdr_is_tcp;
    wire        hdr_is_udp;
    wire        hdr_is_roce;
    wire [47:0] dst_mac;
    wire [47:0] src_mac;
    wire [15:0] ethertype;
    wire [31:0] src_ip;
    wire [31:0] dst_ip;
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

    wire        icrc_valid;
    wire [31:0] icrc;
    wire        icrc_ok;
    wire        icrc_err;
    wire        icrc_skip;

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
    int n_ipv4, n_non_ipv4, n_truncated;
    int n_tcp, n_udp, n_roce;
    int n_msg, n_ack, n_psn_err, n_op_err;
    int n_hs, n_tcp_seq_ok, n_tcp_seq_err, n_tcp_op_err;
    int n_len_mis, n_fin, n_rst, n_psn_gap;
    int n_icrc_ok, n_icrc_err, n_icrc_skip;
    bit pace;
    bit bp;
    int pace_max_us;
    int idle_cyc;
    longint prev_ts_sec;
    int prev_ts_usec;
    longint delta_us;
    int pace_arg;
    int bp_arg;
    string pcap_name;
    string pcap_arg;

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
        .is_non_ipv4(hdr_is_non_ipv4),
        .is_truncated(hdr_is_truncated),
        .is_tcp(hdr_is_tcp),
        .is_udp(hdr_is_udp),
        .is_roce(hdr_is_roce),
        .dst_mac(dst_mac),
        .src_mac(src_mac),
        .ethertype(ethertype),
        .src_ip(src_ip),
        .dst_ip(dst_ip),
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
        .src_ip(src_ip),
        .dst_ip(dst_ip),
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

    always #5 clk = ~clk;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            tready <= 1'b1;
        else if (bp)
            tready <= ~tready;
        else
            tready <= 1'b1;
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

    always @(posedge clk) begin
        if (rst_n && is_len_mismatch) begin
            n_len_mis = n_len_mis + 1;
            $display("[DUT] LEN_MISMATCH  captured=%0d  expected=%0d (14+iplen)",
                     pkt_bytes, 14 + ip_tot_len);
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
        if (rst_n && hdr_valid) begin
            if (hdr_is_truncated)
                n_truncated = n_truncated + 1;
            else if (hdr_is_ipv4)
                n_ipv4 = n_ipv4 + 1;
            else
                n_non_ipv4 = n_non_ipv4 + 1;
            if (hdr_is_tcp)  n_tcp  = n_tcp + 1;
            if (hdr_is_udp)  n_udp  = n_udp + 1;
            if (hdr_is_roce) n_roce = n_roce + 1;

            if (hdr_is_roce) begin
                if (bth_ackreq)
                    $display("[HDR] dst=%012h  src=%012h  etype=0x%04h  IPv4 ttl=%0d iplen=%0d  %0d.%0d.%0d.%0d:%0d -> %0d.%0d.%0d.%0d:%0d  ROCE %s qp=0x%0h psn=0x%0h pkey=0x%04h AckReq",
                             dst_mac, src_mac, ethertype, ip_ttl, ip_tot_len,
                             src_ip[31:24], src_ip[23:16], src_ip[15:8], src_ip[7:0], src_port,
                             dst_ip[31:24], dst_ip[23:16], dst_ip[15:8], dst_ip[7:0], dst_port,
                             bth_opname(bth_opcode), dest_qp, bth_psn, bth_pkey);
                else
                    $display("[HDR] dst=%012h  src=%012h  etype=0x%04h  IPv4 ttl=%0d iplen=%0d  %0d.%0d.%0d.%0d:%0d -> %0d.%0d.%0d.%0d:%0d  ROCE %s qp=0x%0h psn=0x%0h pkey=0x%04h",
                             dst_mac, src_mac, ethertype, ip_ttl, ip_tot_len,
                             src_ip[31:24], src_ip[23:16], src_ip[15:8], src_ip[7:0], src_port,
                             dst_ip[31:24], dst_ip[23:16], dst_ip[15:8], dst_ip[7:0], dst_port,
                             bth_opname(bth_opcode), dest_qp, bth_psn, bth_pkey);
            end else
                $display("[HDR] dst=%012h  src=%012h  etype=0x%04h  %s ttl=%0d iplen=%0d  %0d.%0d.%0d.%0d:%0d -> %0d.%0d.%0d.%0d:%0d  %s",
                         dst_mac, src_mac, ethertype,
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
        packet_count = 0;
        n_runt = 0;
        n_standard = 0;
        n_jumbo = 0;
        n_ipv4 = 0;
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
        max_packets = 8;
        pace_arg = 0;
        pace = 1'b0;
        bp_arg = 0;
        bp = 1'b0;
        pace_max_us = 100;
        prev_ts_sec = 0;
        prev_ts_usec = 0;
        pcap_name = "traffic.pcap";
        void'($value$plusargs("MAX_PACKETS=%d", max_packets));
        if ($value$plusargs("PCAP=%s", pcap_arg) && pcap_arg.len() != 0)
            pcap_name = pcap_arg;
        void'($value$plusargs("PACE=%d", pace_arg));
        void'($value$plusargs("PACE_MAX_US=%d", pace_max_us));
        void'($value$plusargs("BP=%d", bp_arg));
        pace = (pace_arg != 0);
        bp   = (bp_arg != 0);

        #20;
        rst_n = 1;
        #10;

        $display("[SV] Opening %s", pcap_name);
        if (pcap_name.len() == 0 || open_pcap(pcap_name) != 0) begin
            $display("[SV] Failed to open PCAP file. Exiting.");
            $finish;
        end else begin

        dlt = get_datalink();
        $display("[SV] Datalink DLT=%0d%s", dlt, (dlt == 1) ? " (Ethernet)" : "");
        if (DATA_W != 8)
            $display("[SV] AXIS DATA_W=%0d (%0d bytes/beat)", DATA_W, KEEP_W);
        $display("[SV] Streaming up to %0d packets%s%s",
                 max_packets,
                 pace ? $sformatf(" (PACE=1, IFG cap %0d us)", pace_max_us) : "",
                 bp ? " (BP=1, tready 50%)" : "");

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
                do @(posedge clk); while (!tready);
            end

            @(negedge clk);
            tvalid = 0;
            tstart = 0;
            tlast  = 0;
            tdata  = '0;
            tkeep  = '0;
            repeat (3) @(posedge clk);
        end

        close_pcap();
        $display("\n[SV] Simulation finished. File=%s  Streamed %0d packets.", pcap_name, packet_count);
        $display("[DUT] Size    runt=%0d  standard=%0d  jumbo=%0d",
                 n_runt, n_standard, n_jumbo);
        $display("[DUT] Header  ipv4=%0d  tcp=%0d  udp=%0d  roce=%0d  other=%0d  trunc=%0d",
                 n_ipv4, n_tcp, n_udp, n_roce, n_non_ipv4, n_truncated);
        $display("[DUT] Tracker msg=%0d  ack=%0d  psn_err=%0d  op_err=%0d  psn_gap=%0d",
                 n_msg, n_ack, n_psn_err, n_op_err, n_psn_gap);
        $display("[DUT] TCP     hs=%0d  fin=%0d  rst=%0d  seq_ok=%0d  seq_err=%0d  op_err=%0d",
                 n_hs, n_fin, n_rst, n_tcp_seq_ok, n_tcp_seq_err, n_tcp_op_err);
        $display("[DUT] Length  mismatch=%0d", n_len_mis);
        $display("[DUT] ICRC    ok=%0d  err=%0d  skip=%0d",
                 n_icrc_ok, n_icrc_err, n_icrc_skip);
        $finish;
        end
    end

endmodule
