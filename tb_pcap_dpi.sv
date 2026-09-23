`timescale 1ns/1ps

module tb_pcap_dpi;

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
    reg [7:0] tdata;
    reg       tvalid;
    reg       tstart;
    reg       tlast;

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
    wire [7:0]  ip_proto;
    wire [15:0] src_port;
    wire [15:0] dst_port;
    wire [7:0]  bth_opcode;
    wire [23:0] dest_qp;
    wire [23:0] bth_psn;

    int pkt_len;
    int pkt_wire;
    int dlt;
    longint ts_sec;
    int ts_usec;
    int i;
    int packet_count;
    int max_packets;
    int n_runt, n_standard, n_jumbo;
    int n_ipv4, n_non_ipv4, n_truncated;
    int n_tcp, n_udp, n_roce;
    string pcap_name;

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

    pkt_size_filter #(
        .JUMBO_THRESH(1500),
        .MIN_FRAME(64)
    ) u_filter (
        .clk(clk),
        .rst_n(rst_n),
        .tdata(tdata),
        .tvalid(tvalid),
        .tstart(tstart),
        .tlast(tlast),
        .pkt_done(pkt_done),
        .pkt_bytes(pkt_bytes),
        .is_runt(is_runt),
        .is_standard(is_standard),
        .is_jumbo(is_jumbo)
    );

    pkt_header_parser u_parser (
        .clk(clk),
        .rst_n(rst_n),
        .tdata(tdata),
        .tvalid(tvalid),
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
        .ip_proto(ip_proto),
        .src_port(src_port),
        .dst_port(dst_port),
        .bth_opcode(bth_opcode),
        .dest_qp(dest_qp),
        .bth_psn(bth_psn)
    );

    always #5 clk = ~clk;

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

            $display("[HDR] dst=%012h  src=%012h  etype=0x%04h  %s  %0d.%0d.%0d.%0d:%0d -> %0d.%0d.%0d.%0d:%0d  %s",
                     dst_mac, src_mac, ethertype,
                     hdr_is_truncated ? "TRUNC" :
                     hdr_is_ipv4      ? "IPv4"  :
                                        "NON-IPv4",
                     src_ip[31:24], src_ip[23:16], src_ip[15:8], src_ip[7:0], src_port,
                     dst_ip[31:24], dst_ip[23:16], dst_ip[15:8], dst_ip[7:0], dst_port,
                     hdr_is_roce ? $sformatf("ROCE %s qp=0x%0h psn=0x%0h",
                                             bth_opname(bth_opcode), dest_qp, bth_psn) :
                     hdr_is_tcp  ? "TCP"  :
                     hdr_is_udp  ? "UDP"  : "");
        end
    end

    initial begin
        $dumpfile("simulation_trace.vcd");
        $dumpvars(0, tb_pcap_dpi);
    end

    initial begin
        clk = 0;
        rst_n = 0;
        tdata = 0;
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
        max_packets = 8;
        pcap_name = "traffic.pcap";
        void'($value$plusargs("MAX_PACKETS=%d", max_packets));
        void'($value$plusargs("PCAP=%s", pcap_name));

        #20;
        rst_n = 1;
        #10;

        $display("[SV] Opening %s", pcap_name);
        if (open_pcap(pcap_name) != 0) begin
            $display("[SV] Failed to open PCAP file. Exiting.");
            $finish;
        end

        dlt = get_datalink();
        $display("[SV] Datalink DLT=%0d%s", dlt, (dlt == 1) ? " (Ethernet)" : "");
        $display("[SV] Streaming up to %0d packets", max_packets);

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

            for (i = 0; i < pkt_len; i = i + 1) begin
                @(negedge clk);
                tdata  = get_packet_byte();
                tvalid = 1;
                tstart = (i == 0);
                tlast  = (i == pkt_len - 1);
            end

            @(negedge clk);
            tvalid = 0;
            tstart = 0;
            tlast  = 0;
            tdata  = 0;
            repeat (3) @(posedge clk);
        end

        close_pcap();
        $display("\n[SV] Simulation finished. File=%s  Streamed %0d packets.", pcap_name, packet_count);
        $display("[DUT] Size    runt=%0d  standard=%0d  jumbo=%0d",
                 n_runt, n_standard, n_jumbo);
        $display("[DUT] Header  ipv4=%0d  tcp=%0d  udp=%0d  roce=%0d  other=%0d  trunc=%0d",
                 n_ipv4, n_tcp, n_udp, n_roce, n_non_ipv4, n_truncated);
        $finish;
    end

endmodule
