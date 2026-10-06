// IRQ monitor (agent-shaped BFM, not Accellera UVM).
// Counts one-cycle pulses on irq_rx.

`timescale 1ns/1ps

module tb_irq_monitor (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        irq,
    output logic [31:0] pulse_count
);

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            pulse_count <= 32'd0;
        else if (irq)
            pulse_count <= pulse_count + 32'd1;
    end

endmodule
