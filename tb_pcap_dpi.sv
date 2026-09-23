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

    int pkt_len;
    int i;
    int packet_count;
    int max_packets;
    int n_runt;
    int n_standard;
    int n_jumbo;

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
        max_packets = 8;
        void'($value$plusargs("MAX_PACKETS=%d", max_packets));

        #20;
        rst_n = 1;
        #10;

        if (open_pcap("traffic.pcap") != 0) begin
            $display("[SV] Failed to open PCAP file. Exiting.");
            $finish;
        end

        $display("[SV] Streaming up to %0d packets into pkt_size_filter", max_packets);

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
        $display("[DUT] Totals  runt=%0d  standard=%0d  jumbo=%0d",
                 n_runt, n_standard, n_jumbo);
        $finish;
    end

endmodule
