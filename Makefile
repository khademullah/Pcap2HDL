# ==============================================================================
# PCAP Hardware-Software Verification Environment Makefile
# ==============================================================================

# Toolchain configuration
VERILATOR = verilator
TOP_MODULE = tb_pcap_dpi
WAVE_VIEWER = gtkwave

# Source files
SV_SOURCES = tb_pcap_dpi.sv pkt_size_filter.sv
C_SOURCES  = pcap_reader.c
WAVE_FILE  = simulation_trace.vcd
LOG_FILE   = simulation.log

# Default packet cap stays small: traffic.pcap is jumbo-heavy (~35 KB avg).
MAX_PACKETS ?= 8

# Verilator compilation flags
# --binary: Compiles everything down to a native executable
# --timing: Enables SystemVerilog delays (# delay statements)
# --trace:  Injects waveform dumping hooks
VERILATOR_FLAGS = --binary --timing --trace -j 0 --top-module $(TOP_MODULE)
LDFLAGS         = -LDFLAGS "-lpcap"

# Default target
.PHONY: all
all: run

# Compile the design and link libraries
.PHONY: compile
compile: $(SV_SOURCES) $(C_SOURCES)
	@echo "[MAKE] Verilating and compiling hardware-software layers..."
	$(VERILATOR) $(VERILATOR_FLAGS) $(SV_SOURCES) $(C_SOURCES) $(LDFLAGS)

# Run the compiled simulation binary and log output
.PHONY: run
run: compile
	@echo "[MAKE] Launching PCAP stream simulation..."
	@if [ ! -f ./obj_dir/V$(TOP_MODULE) ]; then \
		echo "[ERROR] Compiled executable not found!"; exit 1; \
	fi
	./obj_dir/V$(TOP_MODULE) +MAX_PACKETS=$(MAX_PACKETS) | tee $(LOG_FILE)

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
	@echo "  make run      - Compile and run simulation (MAX_PACKETS=$(MAX_PACKETS))"
	@echo "  make wave     - Open simulation trace in GTKWave background"
	@echo "  make clean    - Remove build artifacts, waveforms, and logs"
