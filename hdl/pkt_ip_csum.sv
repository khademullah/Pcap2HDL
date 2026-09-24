// IPv4 header checksum (RFC 1071). Same fold as dpi/pcap_reader.c.
// Ones-complement sum of the IHL words, including the checksum field,
// must fold to 16'hffff. Non-IPv4 and truncated headers are skipped.

`timescale 1ns/1ps

module pkt_ip_csum #(
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

    output logic        csum_valid,
    output logic        csum_ok,
    output logic        csum_err,
    output logic        csum_skip,
    output logic [15:0] csum
);

    localparam int KEEP_W = DATA_W / 8;
    localparam logic [15:0] ETYPE_IPV4 = 16'h0800;

    logic [15:0] idx;
    logic [15:0] etype;
    logic [3:0]  ihl;
    logic [31:0] acc;
    logic [7:0]  hold;
    logic        have_hold;
    logic        saw_ip;
    logic        done;

    logic [15:0] idx_w;
    logic [15:0] etype_w;
    logic [3:0]  ihl_w;
    logic [31:0] acc_w;
    logic [7:0]  hold_w;
    logic        have_hold_w;
    logic        saw_ip_w;
    logic        done_w;
    logic [7:0]  b_w;
    logic        more_keep;
    logic        last_b;
    logic [15:0] ip_last;
    logic [31:0] f;
    logic [15:0] folded;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            idx       <= 16'd0;
            etype     <= 16'd0;
            ihl       <= 4'd5;
            acc       <= 32'd0;
            hold      <= 8'd0;
            have_hold <= 1'b0;
            saw_ip    <= 1'b0;
            done      <= 1'b0;
            csum_valid <= 1'b0;
            csum_ok    <= 1'b0;
            csum_err   <= 1'b0;
            csum_skip  <= 1'b0;
            csum       <= 16'd0;
        end else begin
            csum_valid <= 1'b0;
            csum_ok    <= 1'b0;
            csum_err   <= 1'b0;
            csum_skip  <= 1'b0;

            if (tvalid && tready) begin
                if (tstart) begin
                    idx_w       = 16'd0;
                    etype_w     = 16'd0;
                    ihl_w       = 4'd5;
                    acc_w       = 32'd0;
                    hold_w      = 8'd0;
                    have_hold_w = 1'b0;
                    saw_ip_w    = 1'b0;
                    done_w      = 1'b0;
                end else begin
                    idx_w       = idx;
                    etype_w     = etype;
                    ihl_w       = ihl;
                    acc_w       = acc;
                    hold_w      = hold;
                    have_hold_w = have_hold;
                    saw_ip_w    = saw_ip;
                    done_w      = done;
                end

                for (int lane = 0; lane < KEEP_W; lane++) begin
                    if (tkeep[lane] && !done_w) begin
                        b_w = tdata[8*lane +: 8];
                        more_keep = 1'b0;
                        for (int j = lane + 1; j < KEEP_W; j++)
                            if (tkeep[j])
                                more_keep = 1'b1;
                        last_b = tlast && !more_keep;

                        if (idx_w == 16'd12)
                            etype_w[15:8] = b_w;
                        else if (idx_w == 16'd13)
                            etype_w[7:0] = b_w;

                        if (idx_w == 16'd13)
                            saw_ip_w = (etype_w == ETYPE_IPV4);

                        if (saw_ip_w && idx_w >= 16'd14) begin
                            if (idx_w == 16'd14)
                                ihl_w = (b_w[3:0] < 4'd5) ? 4'd5 : b_w[3:0];
                            if (!have_hold_w) begin
                                hold_w      = b_w;
                                have_hold_w = 1'b1;
                            end else begin
                                acc_w       = acc_w + {16'd0, hold_w, b_w};
                                have_hold_w = 1'b0;
                            end
                            ip_last = 16'd14 + {10'd0, ihl_w, 2'b00} - 16'd1;
                            if (idx_w == ip_last) begin
                                f = acc_w;
                                f = (f & 32'hffff) + (f >> 16);
                                f = (f & 32'hffff) + (f >> 16);
                                folded     = f[15:0];
                                csum       <= folded;
                                csum_valid <= 1'b1;
                                csum_ok    <= (folded == 16'hffff);
                                csum_err   <= (folded != 16'hffff);
                                done_w     = 1'b1;
                            end
                        end

                        if (!done_w && last_b && (!saw_ip_w || idx_w < 16'd14 ||
                            idx_w < (16'd14 + {10'd0, ihl_w, 2'b00} - 16'd1))) begin
                            csum_valid <= 1'b1;
                            csum_skip  <= 1'b1;
                            done_w     = 1'b1;
                        end

                        idx_w = idx_w + 16'd1;
                    end
                end

                idx       <= idx_w;
                etype     <= etype_w;
                ihl       <= ihl_w;
                acc       <= acc_w;
                hold      <= hold_w;
                have_hold <= have_hold_w;
                saw_ip    <= saw_ip_w;
                done      <= done_w;
            end
        end
    end

endmodule
