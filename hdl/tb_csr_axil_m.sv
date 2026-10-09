// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Khadem Ullah

// AXI-Lite CSR master (agent-shaped BFM, not Accellera UVM).
// Clocked req/done FSM so Verilator --timing can schedule it.

`timescale 1ns/1ps

module tb_csr_axil_m (
    input  logic        clk,
    input  logic        rst_n,

    input  logic        req,
    input  logic        req_write,
    input  logic [7:0]  req_addr,
    input  logic [31:0] req_wdata,
    output logic        done,
    output logic [31:0] rsp_rdata,
    output logic [1:0]  rsp_resp,

    output logic [7:0]  awaddr,
    output logic        awvalid,
    input  logic        awready,
    output logic [31:0] wdata,
    output logic [3:0]  wstrb,
    output logic        wvalid,
    input  logic        wready,
    input  logic [1:0]  bresp,
    input  logic        bvalid,
    output logic        bready,
    output logic [7:0]  araddr,
    output logic        arvalid,
    input  logic        arready,
    input  logic [31:0] rdata,
    input  logic [1:0]  rresp,
    input  logic        rvalid,
    output logic        rready
);

    typedef enum logic [2:0] {
        ST_IDLE  = 3'd0,
        ST_WDATA = 3'd1,
        ST_WRESP = 3'd2,
        ST_RADDR = 3'd3,
        ST_RDATA = 3'd4,
        ST_DONE  = 3'd5
    } state_t;

    state_t     state;
    logic       aw_acc;
    logic       w_acc;
    logic [1:0] last_resp;

    assign rsp_resp = last_resp;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state     <= ST_IDLE;
            done      <= 1'b0;
            rsp_rdata <= 32'd0;
            awaddr    <= 8'd0;
            awvalid   <= 1'b0;
            wdata     <= 32'd0;
            wstrb     <= 4'd0;
            wvalid    <= 1'b0;
            bready    <= 1'b0;
            araddr    <= 8'd0;
            arvalid   <= 1'b0;
            rready    <= 1'b0;
            aw_acc    <= 1'b0;
            w_acc     <= 1'b0;
            last_resp <= 2'b00;
        end else begin
            unique case (state)
                ST_IDLE: begin
                    awvalid <= 1'b0;
                    wvalid  <= 1'b0;
                    bready  <= 1'b0;
                    arvalid <= 1'b0;
                    rready  <= 1'b0;
                    aw_acc  <= 1'b0;
                    w_acc   <= 1'b0;
                    if (req && req_write) begin
                        done    <= 1'b0;
                        awaddr  <= req_addr;
                        wdata   <= req_wdata;
                        wstrb   <= 4'hF;
                        awvalid <= 1'b1;
                        wvalid  <= 1'b1;
                        bready  <= 1'b1;
                        state   <= ST_WDATA;
                    end else if (req && !req_write) begin
                        done    <= 1'b0;
                        araddr  <= req_addr;
                        arvalid <= 1'b1;
                        rready  <= 1'b1;
                        state   <= ST_RADDR;
                    end
                end
                ST_WDATA: begin
                    if (awvalid && awready) begin
                        aw_acc  <= 1'b1;
                        awvalid <= 1'b0;
                    end
                    if (wvalid && wready) begin
                        w_acc  <= 1'b1;
                        wvalid <= 1'b0;
                    end
                    if ((aw_acc || (awvalid && awready)) &&
                        (w_acc  || (wvalid && wready)))
                        state <= ST_WRESP;
                end
                ST_WRESP: begin
                    if (bvalid && bready) begin
                        last_resp <= bresp;
                        bready    <= 1'b0;
                        state     <= ST_DONE;
                    end
                end
                ST_RADDR: begin
                    if (arvalid && arready) begin
                        arvalid <= 1'b0;
                        state   <= ST_RDATA;
                    end
                end
                ST_RDATA: begin
                    if (rvalid && rready) begin
                        last_resp <= rresp;
                        rsp_rdata <= rdata;
                        rready    <= 1'b0;
                        state     <= ST_DONE;
                    end
                end
                ST_DONE: begin
                    done  <= 1'b1;
                    state <= ST_IDLE;
                end
                default: state <= ST_IDLE;
            endcase
        end
    end

endmodule
