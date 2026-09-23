// Streaming packet-length classifier.
// Counts AXI-Stream tkeep bits (DATA_W=8 is one byte per cycle).

`timescale 1ns/1ps

module pkt_size_filter #(
    parameter int DATA_W       = 8,
    parameter int JUMBO_THRESH = 1500,
    parameter int MIN_FRAME    = 64
) (
    input  logic                clk,
    input  logic                rst_n,
    input  logic [DATA_W-1:0]   tdata,
    input  logic [DATA_W/8-1:0] tkeep,
    input  logic                tvalid,
    input  logic                tstart,
    input  logic                tlast,

    output logic        pkt_done,
    output logic [31:0] pkt_bytes,
    output logic        is_runt,
    output logic        is_standard,
    output logic        is_jumbo
);

    localparam int KEEP_W = DATA_W / 8;

    typedef enum logic [1:0] {
        ST_IDLE  = 2'd0,
        ST_COUNT = 2'd1
    } state_t;

    state_t      state;
    logic [31:0] count;
    logic [31:0] beat_bytes;

    wire unused_tdata = |tdata;

    always_comb begin
        beat_bytes = 32'd0;
        for (int i = 0; i < KEEP_W; i++)
            beat_bytes = beat_bytes + {31'd0, tkeep[i]};
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state       <= ST_IDLE;
            count       <= 32'd0;
            pkt_done    <= 1'b0;
            pkt_bytes   <= 32'd0;
            is_runt     <= 1'b0;
            is_standard <= 1'b0;
            is_jumbo    <= 1'b0;
        end else begin
            pkt_done <= 1'b0;

            unique case (state)
                ST_IDLE: begin
                    if (tvalid && tstart) begin
                        count <= beat_bytes;
                        if (tlast)
                            classify(beat_bytes);
                        else
                            state <= ST_COUNT;
                    end
                end
                ST_COUNT: begin
                    if (tvalid) begin
                        if (tlast) begin
                            classify(count + beat_bytes);
                            count <= 32'd0;
                            state <= ST_IDLE;
                        end else begin
                            count <= count + beat_bytes;
                        end
                    end
                end
                default: state <= ST_IDLE;
            endcase
        end
    end

    task automatic classify(input logic [31:0] nbytes);
        pkt_done    <= 1'b1;
        pkt_bytes   <= nbytes;
        is_runt     <= (nbytes < MIN_FRAME);
        is_jumbo    <= (nbytes > JUMBO_THRESH);
        is_standard <= (nbytes >= MIN_FRAME) && (nbytes <= JUMBO_THRESH);
    endtask

endmodule
