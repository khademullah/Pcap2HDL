// Example NIC RX: AXI-Stream *slave* (drives tready).
// Swap this module for your MAC/RX; keep the s_* port list.
// Occupancy is a credit FIFO: the host side drains one beat per cycle.
// Advances only on s_tvalid && s_tready. Bench BP is ready_mask, AND-ed here
// so wr matches the bus (do not AND tready only outside the slave).

`timescale 1ns/1ps

module nic_rx #(
    parameter int DATA_W = 8,
    parameter int DEPTH  = 16
) (
    input  logic                clk,
    input  logic                rst_n,

    input  logic [DATA_W-1:0]   s_tdata,
    input  logic [DATA_W/8-1:0] s_tkeep,
    input  logic                s_tvalid,
    output logic                s_tready,
    input  logic                s_tstart,
    input  logic                s_tlast,
    input  logic [31:0]         s_tuser,
    input  logic                s_tuser_err,

    // AND-ed into s_tready (bench BP). Your NIC can tie this 1 and drive ready alone.
    input  logic                ready_mask,

    // Optional extra stall from the bench (plusarg NIC_PAUSE=1 toggles inside).
    input  logic                pause_en,

    // AXI-Lite CSR: 0x00 CTRL, 0x04 STATUS (rx count), 0x08 OCC.
    input  logic [7:0]          s_axil_awaddr,
    input  logic                s_axil_awvalid,
    output logic                s_axil_awready,
    input  logic [31:0]         s_axil_wdata,
    input  logic [3:0]          s_axil_wstrb,
    input  logic                s_axil_wvalid,
    output logic                s_axil_wready,
    output logic [1:0]          s_axil_bresp,
    output logic                s_axil_bvalid,
    input  logic                s_axil_bready,
    input  logic [7:0]          s_axil_araddr,
    input  logic                s_axil_arvalid,
    output logic                s_axil_arready,
    output logic [31:0]         s_axil_rdata,
    output logic [1:0]          s_axil_rresp,
    output logic                s_axil_rvalid,
    input  logic                s_axil_rready,

    output logic                irq_rx,

    output logic                rx_pkt_valid,
    output logic [31:0]         rx_bytes,
    output logic [31:0]         rx_hash,
    output logic                rx_err,
    output logic                rx_drop,
    output logic [15:0]         rx_occ
);

    localparam int KEEP_W = DATA_W / 8;
    localparam int CW     = $clog2(DEPTH + 1);

    logic [CW-1:0] count;
    logic [CW-1:0] count_n;
    logic          wr;
    logic          rd;
    logic          almost_full;
    logic          bubble;
    logic [31:0]   acc;
    logic [31:0]   beat_bytes;
    logic          in_pkt;
    logic          rx_en;
    logic          pause_csr;
    logic          irq_en;
    logic [31:0]   csr_rx_count;
    logic          got_aw;
    logic          got_w;
    logic [7:0]    wr_addr;
    logic [31:0]   wr_data;

    always_comb begin
        beat_bytes = 32'd0;
        for (int i = 0; i < KEEP_W; i++)
            beat_bytes = beat_bytes + {31'd0, s_tkeep[i]};
    end

    assign wr          = s_tvalid && s_tready;
    assign rd          = (count != '0);
    assign almost_full = (count >= CW'(DEPTH - 2));
    assign s_tready    = rst_n && rx_en && ready_mask && !bubble && !almost_full;
    assign irq_rx      = rst_n && irq_en && rx_pkt_valid;

    assign s_axil_awready = rst_n && !got_aw && !s_axil_bvalid;
    assign s_axil_wready  = rst_n && !got_w && !s_axil_bvalid;
    assign s_axil_arready = rst_n && !s_axil_rvalid;
    assign s_axil_bresp   = 2'b00;
    assign s_axil_rresp   = 2'b00;

    always_comb begin
        unique case ({wr, rd})
            2'b10:   count_n = count + 1'b1;
            2'b01:   count_n = count - 1'b1;
            default: count_n = count;
        endcase
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            count        <= '0;
            bubble       <= 1'b0;
            acc          <= 32'd0;
            in_pkt       <= 1'b0;
            rx_pkt_valid <= 1'b0;
            rx_bytes     <= 32'd0;
            rx_hash      <= 32'd0;
            rx_err       <= 1'b0;
            rx_drop      <= 1'b0;
            rx_occ       <= 16'd0;
            rx_en        <= 1'b1;
            pause_csr    <= 1'b0;
            irq_en       <= 1'b1;
            csr_rx_count <= 32'd0;
            got_aw       <= 1'b0;
            got_w        <= 1'b0;
            wr_addr      <= 8'd0;
            wr_data      <= 32'd0;
            s_axil_bvalid <= 1'b0;
            s_axil_rvalid <= 1'b0;
            s_axil_rdata  <= 32'd0;
        end else begin
            count        <= count_n;
            rx_occ       <= 16'(count_n);
            rx_pkt_valid <= 1'b0;
            rx_drop      <= 1'b0;
            if (pause_en || pause_csr)
                bubble <= ~bubble;
            else
                bubble <= 1'b0;

            if (wr && (count >= CW'(DEPTH)))
                rx_drop <= 1'b1;

            if (wr) begin
                if (s_tstart) begin
                    in_pkt  <= 1'b1;
                    acc     <= beat_bytes;
                    rx_hash <= s_tuser;
                    rx_err  <= s_tuser_err;
                end else if (in_pkt) begin
                    acc <= acc + beat_bytes;
                end

                if (s_tlast) begin
                    rx_pkt_valid <= 1'b1;
                    rx_bytes     <= (s_tstart ? beat_bytes : (acc + beat_bytes));
                    acc          <= 32'd0;
                    in_pkt       <= 1'b0;
                    csr_rx_count <= csr_rx_count + 32'd1;
                end
            end

            if (s_axil_awvalid && s_axil_awready) begin
                got_aw  <= 1'b1;
                wr_addr <= s_axil_awaddr;
            end
            if (s_axil_wvalid && s_axil_wready) begin
                got_w   <= 1'b1;
                wr_data <= s_axil_wdata;
            end
            if (got_aw && got_w && !s_axil_bvalid) begin
                got_aw <= 1'b0;
                got_w  <= 1'b0;
                s_axil_bvalid <= 1'b1;
                if (wr_addr[7:2] == 6'h00) begin
                    rx_en     <= wr_data[0];
                    pause_csr <= wr_data[1];
                    irq_en    <= wr_data[2];
                end
            end
            if (s_axil_bvalid && s_axil_bready)
                s_axil_bvalid <= 1'b0;

            if (s_axil_arvalid && s_axil_arready) begin
                s_axil_rvalid <= 1'b1;
                unique case (s_axil_araddr[7:2])
                    6'h00: s_axil_rdata <= {29'd0, irq_en, pause_csr, rx_en};
                    6'h01: s_axil_rdata <= csr_rx_count;
                    6'h02: s_axil_rdata <= {16'd0, rx_occ};
                    default: s_axil_rdata <= 32'd0;
                endcase
            end
            if (s_axil_rvalid && s_axil_rready)
                s_axil_rvalid <= 1'b0;
        end
    end

endmodule
