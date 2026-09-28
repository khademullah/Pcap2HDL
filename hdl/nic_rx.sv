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

    always_comb begin
        beat_bytes = 32'd0;
        for (int i = 0; i < KEEP_W; i++)
            beat_bytes = beat_bytes + {31'd0, s_tkeep[i]};
    end

    assign wr          = s_tvalid && s_tready;
    assign rd          = (count != '0);
    assign almost_full = (count >= CW'(DEPTH - 2));
    assign s_tready    = rst_n && ready_mask && !bubble && !almost_full;

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
        end else begin
            count        <= count_n;
            rx_occ       <= 16'(count_n);
            rx_pkt_valid <= 1'b0;
            rx_drop      <= 1'b0;
            if (pause_en)
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
                end
            end
        end
    end

endmodule
