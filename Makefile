# ==============================================================================
# PCAP Hardware-Software Verification Environment Makefile
# ==============================================================================

# Toolchain configuration
VERILATOR = verilator
TOP_MODULE = tb_pcap_dpi
WAVE_VIEWER = gtkwave

# Source files
HDL_DIR = hdl
DPI_DIR = dpi
# Compile nic_rx only when NIC=1 (rebuilds).
NIC ?= 0
SV_SOURCES = \
	$(HDL_DIR)/tb_pcap_dpi.sv \
	$(HDL_DIR)/pkt_snoop.sv \
	$(HDL_DIR)/pkt_size_filter.sv \
	$(HDL_DIR)/pkt_header_parser.sv \
	$(HDL_DIR)/pkt_roce_tracker.sv \
	$(HDL_DIR)/pkt_tcp_tracker.sv \
	$(HDL_DIR)/pkt_roce_icrc.sv \
	$(HDL_DIR)/pkt_rss.sv \
	$(HDL_DIR)/pkt_ip_csum.sv \
	$(HDL_DIR)/tb_axis_monitor.sv \
	$(HDL_DIR)/tb_irq_monitor.sv \
	$(HDL_DIR)/tb_csr_axil_m.sv
ifeq ($(NIC),1)
SV_SOURCES += $(HDL_DIR)/nic_rx.sv
endif
C_SOURCES  = $(DPI_DIR)/pcap_reader.c
WAVE_FILE  = simulation_trace.vcd
LOG_FILE   = simulation.log

# Default cap: jumbo traces are slow at 1 byte/cycle.
MAX_PACKETS ?= 100
# traffic.pcap = iperf TCP/IP    soft_roce.pcap = Soft-RoCEv2
PCAP ?= traffic.pcap
PACE ?= 0
PACE_MAX_US ?= 100
BP ?= 0
DUMP ?=
FILTER ?=
NIC_PAUSE ?= 0
# 8 = one byte/cycle (default logs). 64 = tdata[63:0] + tkeep.
AXIS_W ?= 8

# Verilator compilation flags
# --binary: Compiles everything down to a native executable
# --timing: Enables SystemVerilog delays (# delay statements)
# --trace:  Injects waveform dumping hooks
VERILATOR_FLAGS = --binary --timing --trace -j 0 --top-module $(TOP_MODULE) -GDATA_W=$(AXIS_W)
ifeq ($(NIC),1)
VERILATOR_FLAGS += -DEN_NIC
endif
LDFLAGS         = -LDFLAGS "-lpcap"

.PHONY: all
all: run

# Compile the design and link libraries
.PHONY: compile
compile: $(SV_SOURCES) $(C_SOURCES)
	@if [ -f obj_dir/.axis_w ] && [ "$$(cat obj_dir/.axis_w)" != "$(AXIS_W)" ]; then \
		echo "[MAKE] AXIS_W changed ($(AXIS_W)); rebuilding..."; \
		rm -rf obj_dir; \
	fi
	@if [ -f obj_dir/.nic_w ] && [ "$$(cat obj_dir/.nic_w)" != "$(NIC)" ]; then \
		echo "[MAKE] NIC=$(NIC) changed; rebuilding..."; \
		rm -rf obj_dir; \
	fi
	@if [ -d obj_dir ] && [ ! -f obj_dir/.src_w ]; then \
		echo "[MAKE] Stale obj_dir; rebuilding..."; \
		rm -rf obj_dir; \
	fi
	@if [ -f obj_dir/.src_w ] && [ "$$(cat obj_dir/.src_w)" != "$(C_SOURCES) $(SV_SOURCES)" ]; then \
		echo "[MAKE] HDL/DPI sources moved; rebuilding..."; \
		rm -rf obj_dir; \
	fi
	@echo "[MAKE] Verilating and compiling hardware-software layers..."
	$(VERILATOR) $(VERILATOR_FLAGS) $(SV_SOURCES) $(C_SOURCES) $(LDFLAGS)
	@echo $(AXIS_W) > obj_dir/.axis_w
	@echo $(NIC) > obj_dir/.nic_w
	@echo "$(C_SOURCES) $(SV_SOURCES)" > obj_dir/.src_w

# Run the compiled simulation binary and log output
.PHONY: run
run: compile
	@echo "[MAKE] Launching PCAP stream simulation..."
	@if [ ! -f ./obj_dir/V$(TOP_MODULE) ]; then \
		echo "[ERROR] Compiled executable not found!"; exit 1; \
	fi
	./obj_dir/V$(TOP_MODULE) +MAX_PACKETS=$(MAX_PACKETS) +PCAP="$(PCAP)" +PACE=$(PACE) +PACE_MAX_US=$(PACE_MAX_US) +BP=$(BP) +NIC_PAUSE=$(NIC_PAUSE) $(if $(DUMP),+DUMP="$(DUMP)",) $(if $(FILTER),+FILTER="$(FILTER)",) | tee $(LOG_FILE)

# Separate path: pyuvm + cocotb on nic_rx (tb/pyuvm). Default `make` does not run this.
PYUVM_VENV ?= /tmp/pcap2hdl-pyuvm
.PHONY: pyuvm
pyuvm:
	@if [ ! -x "$(PYUVM_VENV)/bin/cocotb-config" ]; then \
		echo "[MAKE] Create the pyuvm venv once, then retry:"; \
		echo "  python3 -m venv $(PYUVM_VENV)"; \
		echo "  $(PYUVM_VENV)/bin/pip install 'cocotb==1.9.2' pyuvm"; \
		exit 1; \
	fi
	@echo "[MAKE] pyuvm path → tb/pyuvm (pcap via dpi/pcap_reader.c)"
	@pcap="$(PCAP)"; \
	if [ ! -f "$$pcap" ]; then \
		echo "[MAKE] $$pcap missing; writing ci.pcap"; \
		python3 scripts/gen_pcap.py ci.pcap; \
		pcap=ci.pcap; \
	fi; \
	case $$pcap in /*) ;; *) pcap="$(CURDIR)/$$pcap";; esac; \
	echo "[MAKE] PCAP=$$pcap MAX_PACKETS=$(MAX_PACKETS)"; \
	printf 'PCAP=%s\nMAX_PACKETS=%s\nFILTER=%s\n' "$$pcap" "$(MAX_PACKETS)" "$(FILTER)" > tb/pyuvm/run.env; \
	$(MAKE) -C tb/pyuvm

.PHONY: pyuvm-clean
pyuvm-clean:
	@if [ -f tb/pyuvm/Makefile ]; then $(MAKE) -C tb/pyuvm clean; fi


# Open generated trace file in GTKWave waveform viewer
.PHONY: wave
wave:
	@if [ ! -f $(WAVE_FILE) ]; then \
		echo "[ERROR] Waveform file '$(WAVE_FILE)' not found. Run 'make run' first."; \
		exit 1; \
	fi
	@echo "[MAKE] Opening simulation trace in GTKWave..."
	$(WAVE_VIEWER) $(WAVE_FILE) > /dev/null 2>&1 &

# Clear out build artifacts, executable files, and raw waveforms
.PHONY: clean
clean:
	@echo "[MAKE] Cleaning build artifacts..."
	rm -rf obj_dir/
	rm -f $(WAVE_FILE)
	rm -f $(LOG_FILE)

# Display helper commands
.PHONY: help
help:
	@echo "Available Makefile commands:"
	@echo "  make compile  - Verilate and compile source code"
	@echo "  make run      - Compile and run (PCAP=$(PCAP) MAX_PACKETS=$(MAX_PACKETS))"
	@echo "  make run PCAP=soft_roce.pcap MAX_PACKETS=16"
	@echo "  make run PACE=1                 - IFG from pcap timestamps"
	@echo "  make run BP=1                   - AXI-Stream tready 50% backpressure"
	@echo "  make run BP=2                   - random tready"
	@echo "  make run NIC=1                 - compile nic_rx AXIS slave + CSR/IRQ BFMs + [NIC] summary"
	@echo "  make run NIC=1 NIC_PAUSE=1     - slave toggles s_tready"
	@echo "  make run AXIS_W=64              - 8-byte AXI-Stream beats (rebuilds)"
	@echo "  make run DUMP=replay.pcap       - write AXI-Stream frames back to pcap"
	@echo "  make run FILTER='tcp port 5201' - libpcap BPF before the HDL stream"
	@echo "  make wave     - Open simulation trace in GTKWave background"
	@echo "  make pyuvm MAX_PACKETS=8               - first 8 frames into nic_rx"
	@echo "  make pyuvm FILTER='tcp' MAX_PACKETS=8  - 8 TCP frames into nic_rx"
	@echo "  make clean    - Remove build artifacts, waveforms, and logs"
