// Per-QP RoCEv2 send-sequence tracker.
// Sessions are keyed by {src_ip, dst_ip, dest_qp}. ACK looks up the reverse
// pair so a pingpong (two directions, same QP number) does not mix PSN spaces.

`timescale 1ns/1ps

module pkt_roce_tracker #(
    parameter int NUM_SESS = 4
) (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        hdr_valid,
    input  logic        is_roce,
    input  logic [31:0] src_ip,
    input  logic [31:0] dst_ip,
    input  logic [7:0]  opcode,
    input  logic [23:0] dest_qp,
    input  logic [23:0] psn,

    output logic        evt_valid,
    output logic        psn_err,
    output logic        op_err,
    output logic        sess_full,
    output logic        msg_done,
    output logic        ack_ok,
    output logic        psn_gap
);

    localparam logic [7:0] OP_SEND_FIRST     = 8'h00;
    localparam logic [7:0] OP_SEND_MIDDLE    = 8'h01;
    localparam logic [7:0] OP_SEND_LAST      = 8'h02;
    localparam logic [7:0] OP_SEND_LAST_IMM  = 8'h03;
    localparam logic [7:0] OP_SEND_ONLY      = 8'h04;
    localparam logic [7:0] OP_SEND_ONLY_IMM  = 8'h05;
    localparam logic [7:0] OP_WRITE_FIRST    = 8'h06;
    localparam logic [7:0] OP_WRITE_MIDDLE   = 8'h07;
    localparam logic [7:0] OP_WRITE_LAST     = 8'h08;
    localparam logic [7:0] OP_WRITE_LAST_IMM = 8'h09;
    localparam logic [7:0] OP_WRITE_ONLY     = 8'h0A;
    localparam logic [7:0] OP_WRITE_ONLY_IMM = 8'h0B;
    localparam logic [7:0] OP_READ_REQ       = 8'h0C;
    localparam logic [7:0] OP_ACK            = 8'h11;

    typedef struct packed {
        logic        used;
        logic        in_msg;
        logic        wait_ack;
        logic        saw_msg;
        logic [31:0] src_ip;
        logic [31:0] dst_ip;
        logic [23:0] dest_qp;
        logic [23:0] last_psn;
    } sess_t;

    sess_t sess [NUM_SESS];

    function automatic logic is_first(input logic [7:0] op);
        is_first = (op == OP_SEND_FIRST) || (op == OP_WRITE_FIRST);
    endfunction

    function automatic logic is_middle(input logic [7:0] op);
        is_middle = (op == OP_SEND_MIDDLE) || (op == OP_WRITE_MIDDLE);
    endfunction

    function automatic logic is_last(input logic [7:0] op);
        is_last = (op == OP_SEND_LAST) || (op == OP_SEND_LAST_IMM) ||
                  (op == OP_WRITE_LAST) || (op == OP_WRITE_LAST_IMM);
    endfunction

    function automatic logic is_only(input logic [7:0] op);
        is_only = (op == OP_SEND_ONLY) || (op == OP_SEND_ONLY_IMM) ||
                  (op == OP_WRITE_ONLY) || (op == OP_WRITE_ONLY_IMM) ||
                  (op == OP_READ_REQ);
    endfunction

    integer hit, rev, free_i, i;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            evt_valid <= 1'b0;
            psn_err   <= 1'b0;
            op_err    <= 1'b0;
            sess_full <= 1'b0;
            msg_done  <= 1'b0;
            ack_ok    <= 1'b0;
            psn_gap   <= 1'b0;
            for (i = 0; i < NUM_SESS; i = i + 1)
                sess[i] <= '0;
        end else begin
            evt_valid <= 1'b0;
            psn_err   <= 1'b0;
            op_err    <= 1'b0;
            sess_full <= 1'b0;
            msg_done  <= 1'b0;
            ack_ok    <= 1'b0;
            psn_gap   <= 1'b0;

            if (hdr_valid && is_roce) begin
                evt_valid <= 1'b1;
                hit    = -1;
                rev    = -1;
                free_i = -1;
                for (i = 0; i < NUM_SESS; i = i + 1) begin
                    if (sess[i].used &&
                        sess[i].src_ip == src_ip &&
                        sess[i].dst_ip == dst_ip &&
                        sess[i].dest_qp == dest_qp)
                        hit = i;
                    if (sess[i].used &&
                        sess[i].src_ip == dst_ip &&
                        sess[i].dst_ip == src_ip &&
                        sess[i].dest_qp == dest_qp)
                        rev = i;
                    if (!sess[i].used && free_i < 0)
                        free_i = i;
                end

                if (opcode == OP_ACK) begin
                    if (rev < 0) begin
                        op_err <= 1'b1;
                    end else if (!sess[rev].wait_ack) begin
                        op_err <= 1'b1;
                    end else if (psn != sess[rev].last_psn) begin
                        psn_err <= 1'b1;
                    end else begin
                        ack_ok <= 1'b1;
                        sess[rev].wait_ack <= 1'b0;
                    end
                end else if (is_first(opcode) || is_only(opcode)) begin
                    if (hit < 0) begin
                        if (free_i < 0) begin
                            sess_full <= 1'b1;
                            op_err    <= 1'b1;
                        end else begin
                            hit = free_i;
                            sess[hit].used    <= 1'b1;
                            sess[hit].src_ip  <= src_ip;
                            sess[hit].dst_ip  <= dst_ip;
                            sess[hit].dest_qp <= dest_qp;
                        end
                    end
                    if (hit >= 0) begin
                        if (sess[hit].in_msg)
                            op_err <= 1'b1;
                        if (sess[hit].saw_msg &&
                            (psn != (sess[hit].last_psn + 24'd1)))
                            psn_gap <= 1'b1;
                        sess[hit].last_psn <= psn;
                        if (is_only(opcode)) begin
                            sess[hit].in_msg   <= 1'b0;
                            sess[hit].wait_ack <= 1'b1;
                            sess[hit].saw_msg  <= 1'b1;
                            msg_done           <= 1'b1;
                        end else begin
                            sess[hit].in_msg   <= 1'b1;
                            sess[hit].wait_ack <= 1'b0;
                        end
                    end
                end else if (is_middle(opcode) || is_last(opcode)) begin
                    if (hit < 0 || !sess[hit].in_msg) begin
                        op_err <= 1'b1;
                    end else if (psn != (sess[hit].last_psn + 24'd1)) begin
                        psn_err <= 1'b1;
                    end else begin
                        sess[hit].last_psn <= psn;
                        if (is_last(opcode)) begin
                            sess[hit].in_msg   <= 1'b0;
                            sess[hit].wait_ack <= 1'b1;
                            sess[hit].saw_msg  <= 1'b1;
                            msg_done           <= 1'b1;
                        end
                    end
                end else begin
                    op_err <= 1'b1;
                end
            end
        end
    end

endmodule
