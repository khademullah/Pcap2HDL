// Streaming packet-length classifier.
// Counts AXI-Stream-like bytes (tvalid/tstart/tlast) and tags each frame as
// runt (< MIN_FRAME), standard, or jumbo (> JUMBO_THRESH).

`timescale 1ns/1ps

module pkt_size_filter #(
    parameter int JUMBO_THRESH = 1500,
    parameter int MIN_FRAME    = 64
) (
    input  logic        clk,
    input  logic        rst_n,
    input  logic [7:0]  tdata,
    input  logic        tvalid,
    input  logic        tstart,
    input  logic        tlast,

    output logic        pkt_done,
    output logic [31:0] pkt_bytes,
    output logic        is_runt,
    output logic        is_standard,
    output logic        is_jumbo
);

    typedef enum logic [1:0] {
        ST_IDLE  = 2'd0,
        ST_COUNT = 2'd1
    } state_t;

    state_t      state;
    logic [31:0] count;

    // tdata is part of the stream contract; length classification ignores payload.
    wire unused_tdata = |tdata;

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
                        count <= 32'd1;
                        if (tlast)
                            classify(32'd1);
                        else
                            state <= ST_COUNT;
                    end
                end
                ST_COUNT: begin
                    if (tvalid) begin
                        if (tlast) begin
                            classify(count + 32'd1);
                            count <= 32'd0;
                            state <= ST_IDLE;
                        end else begin
                            count <= count + 32'd1;
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
