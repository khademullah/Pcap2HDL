"""pyuvm AXIS agent on nic_rx; pcap bytes from dpi/pcap_reader.c."""

from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles
from pyuvm import (
    ConfigDB,
    test,
    uvm_agent,
    uvm_analysis_port,
    uvm_driver,
    uvm_env,
    uvm_monitor,
    uvm_sequence,
    uvm_sequence_item,
    uvm_sequencer,
    uvm_subscriber,
    uvm_test,
)
import cocotb

from pcap_dpi import PcapDpi, read_run_env


class AxisBeat(uvm_sequence_item):
    def __init__(self, name="beat"):
        super().__init__(name)
        self.data = 0
        self.keep = 1
        self.start = 0
        self.last = 0
        self.user = 0
        self.err = 0


class AxisDriver(uvm_driver):
    def build_phase(self):
        self.dut = ConfigDB().get(self, "", "DUT")

    async def run_phase(self):
        self.dut.s_tvalid.value = 0
        self.dut.s_tstart.value = 0
        self.dut.s_tlast.value = 0
        self.dut.s_tdata.value = 0
        self.dut.s_tkeep.value = 0
        self.dut.s_tuser.value = 0
        self.dut.s_tuser_err.value = 0
        while True:
            beat = await self.seq_item_port.get_next_item()
            await RisingEdge(self.dut.clk)
            self.dut.s_tdata.value = beat.data
            self.dut.s_tkeep.value = beat.keep
            self.dut.s_tstart.value = beat.start
            self.dut.s_tlast.value = beat.last
            self.dut.s_tuser.value = beat.user
            self.dut.s_tuser_err.value = beat.err
            self.dut.s_tvalid.value = 1
            while True:
                await RisingEdge(self.dut.clk)
                if int(self.dut.s_tready.value) == 1:
                    break
            self.dut.s_tvalid.value = 0
            self.dut.s_tstart.value = 0
            self.dut.s_tlast.value = 0
            self.seq_item_port.item_done()


class AxisMonitor(uvm_monitor):
    def build_phase(self):
        self.dut = ConfigDB().get(self, "", "DUT")
        self.ap = uvm_analysis_port("ap", self)

    async def run_phase(self):
        while True:
            await RisingEdge(self.dut.clk)
            if int(self.dut.s_tvalid.value) == 1 and int(self.dut.s_tready.value) == 1:
                beat = AxisBeat("mon")
                beat.data = int(self.dut.s_tdata.value)
                beat.last = int(self.dut.s_tlast.value)
                self.ap.write(beat)


class IrqScoreboard(uvm_subscriber):
    def __init__(self, name, parent):
        super().__init__(name, parent)
        self.tlast = 0
        self.irq = 0

    def write(self, beat):
        if beat.last:
            self.tlast += 1

    async def run_phase(self):
        dut = ConfigDB().get(self, "", "DUT")
        while True:
            await RisingEdge(dut.clk)
            if int(dut.irq_rx.value) == 1:
                self.irq += 1


class AxisAgent(uvm_agent):
    def build_phase(self):
        self.seqr = uvm_sequencer("seqr", self)
        self.drv = AxisDriver("drv", self)
        self.mon = AxisMonitor("mon", self)

    def connect_phase(self):
        self.drv.seq_item_port.connect(self.seqr.seq_item_export)


class NicEnv(uvm_env):
    def build_phase(self):
        self.axis = AxisAgent("axis", self)
        self.sb = IrqScoreboard("sb", self)

    def connect_phase(self):
        self.axis.mon.ap.connect(self.sb.analysis_export)


class PcapSeq(uvm_sequence):
    def __init__(self, name="pcap"):
        super().__init__(name)
        self.n_pkts = 0

    async def body(self):
        cfg = read_run_env()
        pcap_name = cfg["PCAP"]
        cap = int(cfg["MAX_PACKETS"])
        filt = cfg["FILTER"]
        dpi = PcapDpi()
        dpi.open(pcap_name)
        dpi.set_filter(filt)
        try:
            while self.n_pkts < cap:
                pkt_len = dpi.fetch()
                if pkt_len == 0:
                    break
                rss_ok, rss_hash = dpi.rss()
                err = dpi.csum_err()
                self.n_pkts += 1
                for i in range(pkt_len):
                    beat = AxisBeat(f"p{self.n_pkts}b{i}")
                    beat.data = dpi.byte()
                    beat.keep = 1
                    beat.start = int(i == 0)
                    beat.last = int(i == pkt_len - 1)
                    beat.user = rss_hash if rss_ok else 0
                    beat.err = int(err)
                    await self.start_item(beat)
                    await self.finish_item(beat)
        finally:
            dpi.close()
        if self.n_pkts == 0:
            raise RuntimeError(f"no frames from {pcap_name}")


@test()
class NicPyuvmTest(uvm_test):
    def build_phase(self):
        ConfigDB().set(None, "*", "DUT", cocotb.top)
        self.env = NicEnv("env", self)

    async def run_phase(self):
        self.raise_objection()
        dut = cocotb.top
        cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
        dut.rst_n.value = 0
        dut.s_tvalid.value = 0
        await ClockCycles(dut.clk, 4)
        dut.rst_n.value = 1
        await ClockCycles(dut.clk, 4)
        seq = PcapSeq("seq")
        await seq.start(self.env.axis.seqr)
        await ClockCycles(dut.clk, 16)
        assert self.env.sb.tlast == seq.n_pkts, (
            f"tlast={self.env.sb.tlast} pkts={seq.n_pkts}"
        )
        assert self.env.sb.irq == seq.n_pkts, (
            f"irq={self.env.sb.irq} pkts={seq.n_pkts}"
        )
        cocotb.log.info(f"PcapSeq streamed {seq.n_pkts} frames; tlast and irq match")
        self.drop_objection()
