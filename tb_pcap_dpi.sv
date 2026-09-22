module tb_pcap_dpi;

    // 1. DPI-C Imports must be inside the module and end with semicolons
    import "DPI-C" function int open_pcap(input string filename);
    import "DPI-C" function int fetch_next_packet();
    import "DPI-C" function byte get_packet_byte();

    // 2. Signal and variable declarations
    reg clk;
    reg rst_n;
    reg [7:0] tdata;
    reg       tvalid;
    reg       tstart;
    reg       tlast;

    int pkt_len;
    int i;
    int packet_count;

    // 3. Clock generator
    always #5 clk = ~clk;

    // 4. Initial Block containing the operational simulation logic
    initial begin
        clk = 0;
        rst_n = 0;
        tdata = 0;
        tvalid = 0;
        tstart = 0;
        tlast = 0;
        packet_count = 0;
        
        #20;
        rst_n = 1;
        #10;

        if (open_pcap("traffic.pcap") != 0) begin
            $display("[SV] Failed to open PCAP file. Exiting.");
            $finish;
        end

        while (1) begin
            if (packet_count >= 1000) begin
                $display("\n[SV] Reached target limit of %0d packets. Stopping stream.", packet_count);
                break; 
            end

            pkt_len = fetch_next_packet();
            if (pkt_len == 0) begin
                $display("\n[SV] Reached End of PCAP file before hitting the 1000 packet limit.");
                break; 
            end

            packet_count = packet_count + 1;
            $display("[SV] Processing Packet #%0d (Length: %0d bytes)", packet_count, pkt_len);

            for (i = 0; i < pkt_len; i = i + 1) begin
                @(posedge clk);
                tdata  = get_packet_byte();
                tvalid = 1;
                tstart = (i == 0);
                tlast  = (i == pkt_len - 1);
            end
            
            @(posedge clk);
            tvalid = 0;
            tstart = 0;
            tlast  = 0;
            tdata  = 0;
            repeat(2) @(posedge clk); 
        end

        $display("\n[SV] Simulation finished. Total packets parsed: %0d", packet_count);
        $finish;
    end

endmodule // Make sure the module closes out properly

