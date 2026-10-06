# Optional pyuvm sandbox. Does not replace `make` at the repo root.
# Venv lives outside the repo when the disk is tight, e.g. /tmp/pcap2hdl-pyuvm

PYUVM_VENV ?= /tmp/pcap2hdl-pyuvm
export PATH := $(PYUVM_VENV)/bin:$(PATH)
export PYTHONPATH := $(CURDIR)
export PCAP
export MAX_PACKETS
export FILTER
export PCAP_DPI_SO ?= $(CURDIR)/libpcap_dpi.so

SIM ?= verilator
TOPLEVEL_LANG = verilog
TOPLEVEL = tb_uvm_nic
MODULE = test_nic_pyuvm
VERILOG_SOURCES = $(abspath $(CURDIR)/../../hdl/nic_rx.sv) $(abspath $(CURDIR)/../../hdl/tb_uvm_nic.sv)
EXTRA_ARGS += --trace -Wno-fatal
VERILATOR_INCLUDE ?= /usr/share/verilator/include

include $(shell $(PYUVM_VENV)/bin/cocotb-config --makefiles)/Makefile.sim

# Nested `make results.xml` does not keep parent env; prefix the sim binary.
SIM_CMD_PREFIX += PCAP="$(PCAP)" MAX_PACKETS="$(MAX_PACKETS)" FILTER="$(FILTER)" PCAP_DPI_SO="$(PCAP_DPI_SO)"

.DEFAULT_GOAL := sim

results.xml: libpcap_dpi.so

libpcap_dpi.so: ../../dpi/pcap_reader.c
	$(CC) -shared -fPIC -I$(VERILATOR_INCLUDE) -I$(VERILATOR_INCLUDE)/vltstd -o $@ $< -lpcap
