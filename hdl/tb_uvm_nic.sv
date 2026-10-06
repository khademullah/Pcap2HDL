// Thin wrapper for the pyuvm sandbox (tb/pyuvm). Not used by `make`.
// Clock and AXIS come from Python; AXI-Lite is idle so reset defaults apply.

`timescale 1ns/1ps

module tb_uvm_nic;

    logic        clk;
    logic        rst_n;
    logic [7:0]  s_tdata;
    logic        s_tkeep;
    logic        s_tvalid;
    logic        s_tready;
    logic        s_tstart;
    logic        s_tlast;
    logic [31:0] s_tuser;
    logic        s_tuser_err;
    logic        ready_mask;
    logic        pause_en;
    logic        irq_rx;
    logic        rx_pkt_valid;
    logic [31:0] rx_bytes;
    logic [31:0] rx_hash;
    logic        rx_err;
    logic        rx_drop;
    logic [15:0] rx_occ;

    logic [7:0]  s_axil_awaddr;
    logic        s_axil_awvalid;
    logic        s_axil_awready;
    logic [31:0] s_axil_wdata;
    logic [3:0]  s_axil_wstrb;
    logic        s_axil_wvalid;
    logic        s_axil_wready;
    logic [1:0]  s_axil_bresp;
    logic        s_axil_bvalid;
    logic        s_axil_bready;
    logic [7:0]  s_axil_araddr;
    logic        s_axil_arvalid;
    logic        s_axil_arready;
    logic [31:0] s_axil_rdata;
    logic [1:0]  s_axil_rresp;
    logic        s_axil_rvalid;
    logic        s_axil_rready;

    assign ready_mask      = 1'b1;
    assign pause_en        = 1'b0;
    assign s_axil_awaddr   = 8'd0;
    assign s_axil_awvalid  = 1'b0;
    assign s_axil_wdata    = 32'd0;
    assign s_axil_wstrb    = 4'd0;
    assign s_axil_wvalid   = 1'b0;
    assign s_axil_bready   = 1'b1;
    assign s_axil_araddr   = 8'd0;
    assign s_axil_arvalid  = 1'b0;
    assign s_axil_rready   = 1'b1;

    nic_rx #(
        .DATA_W(8),
        .DEPTH(16)
    ) dut (
        .clk(clk),
        .rst_n(rst_n),
        .s_tdata(s_tdata),
        .s_tkeep(s_tkeep),
        .s_tvalid(s_tvalid),
        .s_tready(s_tready),
        .s_tstart(s_tstart),
        .s_tlast(s_tlast),
        .s_tuser(s_tuser),
        .s_tuser_err(s_tuser_err),
        .ready_mask(ready_mask),
        .pause_en(pause_en),
        .s_axil_awaddr(s_axil_awaddr),
        .s_axil_awvalid(s_axil_awvalid),
        .s_axil_awready(s_axil_awready),
        .s_axil_wdata(s_axil_wdata),
        .s_axil_wstrb(s_axil_wstrb),
        .s_axil_wvalid(s_axil_wvalid),
        .s_axil_wready(s_axil_wready),
        .s_axil_bresp(s_axil_bresp),
        .s_axil_bvalid(s_axil_bvalid),
        .s_axil_bready(s_axil_bready),
        .s_axil_araddr(s_axil_araddr),
        .s_axil_arvalid(s_axil_arvalid),
        .s_axil_arready(s_axil_arready),
        .s_axil_rdata(s_axil_rdata),
        .s_axil_rresp(s_axil_rresp),
        .s_axil_rvalid(s_axil_rvalid),
        .s_axil_rready(s_axil_rready),
        .irq_rx(irq_rx),
        .rx_pkt_valid(rx_pkt_valid),
        .rx_bytes(rx_bytes),
        .rx_hash(rx_hash),
        .rx_err(rx_err),
        .rx_drop(rx_drop),
        .rx_occ(rx_occ)
    );

endmodule
