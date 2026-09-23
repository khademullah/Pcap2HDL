`timescale 1ns/1ps

module tb_pcap_dpi;

    import "DPI-C" function int open_pcap(input string filename);
    import "DPI-C" function int fetch_next_packet();
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
    wire [47:0] dst_mac;
    wire [47:0] src_mac;
    wire [15:0] ethertype;
    wire [31:0] src_ip;
    wire [31:0] dst_ip;

    int pkt_len;
    int i;
    int packet_count;
    int max_packets;
    int n_runt;
    int n_standard;
    int n_jumbo;
    int n_ipv4;
    int n_non_ipv4;
    int n_truncated;

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
        .dst_mac(dst_mac),
        .src_mac(src_mac),
        .ethertype(ethertype),
        .src_ip(src_ip),
        .dst_ip(dst_ip)
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

            $display("[HDR] dst=%012h  src=%012h  etype=0x%04h  %s  %0d.%0d.%0d.%0d -> %0d.%0d.%0d.%0d",
                     dst_mac, src_mac, ethertype,
                     hdr_is_truncated ? "TRUNC" :
                     hdr_is_ipv4      ? "IPv4"  :
                                        "NON-IPv4",
                     src_ip[31:24], src_ip[23:16], src_ip[15:8], src_ip[7:0],
                     dst_ip[31:24], dst_ip[23:16], dst_ip[15:8], dst_ip[7:0]);
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
        max_packets = 8;
        void'($value$plusargs("MAX_PACKETS=%d", max_packets));

        #20;
        rst_n = 1;
        #10;

        if (open_pcap("traffic.pcap") != 0) begin
            $display("[SV] Failed to open PCAP file. Exiting.");
            $finish;
        end

        $display("[SV] Streaming up to %0d packets into size filter + header parser", max_packets);

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

            packet_count = packet_count + 1;
            $display("[SV] Processing Packet #%0d (Length: %0d bytes)", packet_count, pkt_len);

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
        $display("\n[SV] Simulation finished. Streamed %0d packets.", packet_count);
        $display("[DUT] Size    runt=%0d  standard=%0d  jumbo=%0d",
                 n_runt, n_standard, n_jumbo);
        $display("[DUT] Header  ipv4=%0d  non-ipv4=%0d  truncated=%0d",
                 n_ipv4, n_non_ipv4, n_truncated);
        $finish;
    end

endmodule
