// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Khadem Ullah

// AXIS RX monitor (agent-shaped BFM, not Accellera UVM).
// Does not drive the bus. Counts beats and tlast handshakes.

`timescale 1ns/1ps

module tb_axis_monitor (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        tvalid,
    input  logic        tready,
    input  logic        tlast,
    output logic [31:0] pkt_count,
    output logic [31:0] beat_count
);

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            pkt_count  <= 32'd0;
            beat_count <= 32'd0;
        end else if (tvalid && tready) begin
            beat_count <= beat_count + 32'd1;
            if (tlast)
                pkt_count <= pkt_count + 32'd1;
        end
    end

endmodule
