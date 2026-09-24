// RoCEv2 invariant CRC on the last 4 bytes of a complete frame.
// Seed 0xdebb20e3 is CRC32 of a masked 8-byte LRH. Mask TOS/TTL/IPv4
// checksum, UDP checksum, and BTH resv8a (dest-QP high byte). Compare
// ~crc to the ICRC as little-endian. Truncated captures (length != 14+iplen)
// are skipped, not failed.

`timescale 1ns/1ps

module pkt_roce_icrc #(
    parameter int DATA_W = 8
) (
    input  logic                clk,
    input  logic                rst_n,
    input  logic [DATA_W-1:0]   tdata,
    input  logic [DATA_W/8-1:0] tkeep,
    input  logic                tvalid,
    input  logic                tready,
    input  logic                tstart,
    input  logic                tlast,
    input  logic                is_roce,
    input  logic [15:0]         ip_tot_len,

    output logic        icrc_valid,
    output logic [31:0] icrc,
    output logic        icrc_ok,
    output logic        icrc_err,
    output logic        icrc_skip
);

    localparam int KEEP_W = DATA_W / 8;
    localparam logic [31:0] CRC_POLY  = 32'hedb88320;
    localparam logic [31:0] CRC_SEED  = 32'hdebb20e3;

    logic [15:0] idx;
    logic [3:0]  ip_ihl;
    logic [31:0] crc;
    logic [7:0]  d0, d1, d2, d3;
    logic [2:0]  nfill;
    logic [15:0] idx_w;
    logic [3:0]  ihl_w;
    logic [31:0] crc_w;
    logic [7:0]  d0_w, d1_w, d2_w, d3_w;
    logic [2:0]  nfill_w;
    logic [7:0]  b_w;
    logic [15:0] old_idx;
    logic [7:0]  mb;
    logic        do_check;
    logic        match;

    function automatic logic [31:0] crc32_le8(input logic [31:0] c_in, input logic [7:0] data);
        logic [31:0] c;
        c = c_in ^ {24'd0, data};
        for (int i = 0; i < 8; i++)
            c = c[0] ? ({1'b0, c[31:1]} ^ CRC_POLY) : {1'b0, c[31:1]};
        return c;
    endfunction

    function automatic logic [7:0] mask_byte(
        input logic [15:0] eidx,
        input logic [7:0]  raw,
        input logic [3:0]  ihl
    );
        logic [15:0] l4b;
        l4b = 16'd14 + {10'd0, ihl, 2'b00};
        if (eidx == 16'd15 || eidx == 16'd22 || eidx == 16'd24 || eidx == 16'd25)
            mask_byte = 8'hff;
        else if ((eidx == (l4b + 16'd6)) || (eidx == (l4b + 16'd7)))
            mask_byte = 8'hff;
        else if (eidx == (l4b + 16'd12))
            mask_byte = 8'hff;
        else
            mask_byte = raw;
    endfunction

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            idx        <= 16'd0;
            ip_ihl     <= 4'd5;
            crc        <= CRC_SEED;
            d0         <= 8'd0;
            d1         <= 8'd0;
            d2         <= 8'd0;
            d3         <= 8'd0;
            nfill      <= 3'd0;
            icrc_valid <= 1'b0;
            icrc       <= 32'd0;
            icrc_ok    <= 1'b0;
            icrc_err   <= 1'b0;
            icrc_skip  <= 1'b0;
        end else begin
            icrc_valid <= 1'b0;
            icrc_ok    <= 1'b0;
            icrc_err   <= 1'b0;
            icrc_skip  <= 1'b0;

            if (tvalid && tready) begin
                if (tstart) begin
                    idx_w    = 16'd0;
                    ihl_w    = 4'd5;
                    crc_w    = CRC_SEED;
                    d0_w     = 8'd0;
                    d1_w     = 8'd0;
                    d2_w     = 8'd0;
                    d3_w     = 8'd0;
                    nfill_w  = 3'd0;
                end else begin
                    idx_w    = idx;
                    ihl_w    = ip_ihl;
                    crc_w    = crc;
                    d0_w     = d0;
                    d1_w     = d1;
                    d2_w     = d2;
                    d3_w     = d3;
                    nfill_w  = nfill;
                end

                for (int lane = 0; lane < KEEP_W; lane++) begin
                    if (tkeep[lane]) begin
                        b_w = tdata[8*lane +: 8];
                        if (idx_w == 16'd14)
                            ihl_w = b_w[3:0];

                        if (nfill_w == 3'd4) begin
                            old_idx = idx_w - 16'd4;
                            if (old_idx >= 16'd14) begin
                                mb    = mask_byte(old_idx, d0_w, ihl_w);
                                crc_w = crc32_le8(crc_w, mb);
                            end
                            d0_w = d1_w;
                            d1_w = d2_w;
                            d2_w = d3_w;
                            d3_w = b_w;
                        end else begin
                            unique case (nfill_w)
                                3'd0: d0_w = b_w;
                                3'd1: d1_w = b_w;
                                3'd2: d2_w = b_w;
                                default: d3_w = b_w;
                            endcase
                            nfill_w = nfill_w + 3'd1;
                        end
                        idx_w = idx_w + 16'd1;
                    end
                end

                idx       <= idx_w;
                ip_ihl    <= ihl_w;
                crc       <= crc_w;
                d0        <= d0_w;
                d1        <= d1_w;
                d2        <= d2_w;
                d3        <= d3_w;
                nfill     <= nfill_w;

                if (tlast && is_roce) begin
                    icrc      <= {d0_w, d1_w, d2_w, d3_w};
                    do_check  = (nfill_w == 3'd4) && (ip_tot_len != 16'd0) &&
                                (idx_w == (16'd14 + ip_tot_len));
                    match     = ({d3_w, d2_w, d1_w, d0_w} == ((~crc_w) & 32'hffff_ffff));
                    icrc_valid <= 1'b1;
                    if (!do_check)
                        icrc_skip <= 1'b1;
                    else if (match)
                        icrc_ok <= 1'b1;
                    else
                        icrc_err <= 1'b1;
                end
            end
        end
    end

endmodule
