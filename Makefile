# Check for RISCV toolchain env variable
ifndef RISCV
$(error Please set environment variable RISCV to your installed toolchain location (i.e. /opt/riscv/))
endif

# Directories
src_dir = resources/common
template_dir = $(src_dir)/templates
bin_dir = bin

# Specify flags
XLEN ?= 64
RISCV_PREFIX ?= $(RISCV)/bin/riscv$(XLEN)-unknown-elf-
RISCV_GCC ?= $(RISCV_PREFIX)gcc
RISCV_GCC_OPTS ?= -march=rv64g -mabi=lp64d -DPREALLOCATE=1 -mcmodel=medany -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf
RISCV_LINK_OPTS ?= -static -nostdlib -nostartfiles -lm -lgcc -T $(src_dir)/test.ld
RISCV_OBJDUMP ?= $(RISCV_PREFIX)objdump --disassemble --full-contents --disassemble-zeroes --section=.text --section=.text.startup --section=.text.init --section=.data

# Rocket emulator info
MAX_CYCLES ?= 100000000
CONFIG ?= DefaultConfig

# Define sources
SRCS_C=$(wildcard $(src_dir)/*.c) 
SRCS_S=$(wildcard $(src_dir)/*.S)
COMMON_OBJS=$(patsubst $(src_dir)/%.c,$(bin_dir)/%.o,$(SRCS_C)) $(patsubst $(src_dir)/%.S,$(bin_dir)/%.o,$(SRCS_S)) 
OBJS=$(COMMON_OBJS) $(bin_dir)/template.o
UNIT_OBJS=$(COMMON_OBJS) $(bin_dir)/unittemplate.o

# Define template
TEMPLATE ?= base
UNIT_TEMPLATE ?= unit

# Check info!
# $(info SRCS_S is $(SRCS_S))
# $(info SRCS_C is $(SRCS_C))
# $(info OBJS is $(OBJS))

# Headers!
incs  += -I$(src_dir)

default: dump

dump: $(bin_dir)/out.dump $(bin_dir)/jit.bin.dump $(bin_dir)/int.bin.dump

rocket: $(bin_dir)/rocket.log
cva6: $(bin_dir)/cva6.log

rocketwf: $(bin_dir)/rocket.fst
cva6wf: $(bin_dir)/cva6.fst



# Link all the object files!
$(bin_dir)/out.elf: $(OBJS)
	$(RISCV_GCC) $(RISCV_LINK_OPTS) $(OBJS) -o $@

# the objcopy way, the issue with this method is that the labels are auto generated!
# $(bin_dir)/out.o: $(bin_dir)/out.bin
# 	$(RISCV_PREFIX)objcopy -I binary -O elf64-littleriscv -B riscv --rename-section .data=.text $^ $@

define rv-gcc
$(RISCV_GCC) $(incs) $(RISCV_GCC_OPTS) $< -c -o $@ 
endef

# Generate the object files
$(bin_dir)/%.o: $(src_dir)/%.c
	$(rv-gcc)

$(bin_dir)/%.o: $(src_dir)/%.S
	$(rv-gcc)

$(bin_dir)/template.o: $(template_dir)/$(TEMPLATE).S $(bin_dir)/int.bin $(bin_dir)/jit.bin
	$(rv-gcc)

# Dumps
$(bin_dir)/out.dump: $(bin_dir)/out.elf
	$(RISCV_OBJDUMP) $< > $@

$(bin_dir)/%.bin.dump: $(bin_dir)/%.bin
	$(RISCV_PREFIX)objcopy -I binary -O elf64-littleriscv -B riscv --rename-section .data=.text $^ $@.temp
	$(RISCV_OBJDUMP) $@.temp > $@
	rm $@.temp

# Emulator executions
# - Rocket -
# TODO: spike from toolchain
$(bin_dir)/rocket.log: $(bin_dir)/out.elf
ifndef ROCKET
	$(error Please set environment variable ROCKET to the (compiled) Rocket verilator emulator (i.e. rocket/emulator/))
endif
	$(info Trying CONFIG=$(CONFIG), if this is not the expected one, specify it directly)
	$(ROCKET)/emulator-freechips.rocketchip.system-freechips.rocketchip.system.$(CONFIG) +max-cycles=$(MAX_CYCLES) +verbose $< 3>&1 1>&2 2>&3 | spike-dasm > $@


# - CVA6 -
# Note: Make is not happy if the execution fails!
$(bin_dir)/cva6.log: $(bin_dir)/out.elf
ifndef CVA6
	$(error Please set environment variable CVA6 to the (compiled) CVA6 verilator emulator (i.e. cva6/work-ver/Variane_testharness))
endif
	($(CVA6) $< > $@ 2>&1) || true 
	spike-dasm < trace_hart_00.dasm >> $@

# Waveform generation
# - Rocket -
$(bin_dir)/rocket.fst: $(bin_dir)/out.elf
ifndef ROCKET
	$(error Please set environment variable ROCKET to the (compiled) Rocket verilator emulator (i.e.))
endif
	$(info Trying CONFIG=$(CONFIG), if this is not the expected one, specify it directly)
	$(EMULATOR)/emulator-freechips.rocketchip.system-freechips.rocketchip.system.$(CONFIG) -v - +max-cycles=$(MAX_CYCLES) $< | vcd2fst - $@

# - CVA6 -
$(bin_dir)/cva6.fst: $(bin_dir)/out.elf
ifndef EMULATOR
	$(error Please set environment variable EMULATOR to the (compiled) CVA6 verilator emulator (i.e. cva6/work-ver/Variane_testharness))
endif
	($(CVA6) $< -v - | vcd2fst - $@) || true



# Unit tests
unitdump: $(bin_dir)/unit.dump

$(bin_dir)/unit.elf: $(UNIT_OBJS)
	$(RISCV_GCC) $(RISCV_LINK_OPTS) $(UNIT_OBJS) -o $@

$(bin_dir)/unittemplate.o: $(template_dir)/$(TEMPLATE).S $(bin_dir)/unit.bin
	$(rv-gcc) 

$(bin_dir)/unit.dump: $(bin_dir)/unit.elf
	$(RISCV_OBJDUMP) $< > $@

# Aliases for cleanup
DUMPS=$(wildcard $(bin_dir)/*.dump)
BINS=$(wildcard $(bin_dir)/*.bin)
TEMPS=$(wildcard $(bin_dir)/*.temp)
ELFS=$(wildcard $(bin_dir)/*.elf)
CORE_LOGS=$(wildcard $(bin_dir)/*.log)
WAVEFORMS=$(wildcard $(bin_dir)/*.vcd) $(wildcard $(bin_dir)/*.fst)
UNIT_DUMPS=$(wildcard $(bin_dir)/unit/*.dump)
UNIT_ELFS=$(wildcard $(bin_dir)/unit/*.elf)

.PHONY: clean

clean:
	rm -rf $(ELFS) $(OBJS) $(UNIT_OBJS) $(DUMPS) $(TEMPS) $(CORE_LOGS) $(WAVEFORMS)

cleanall: clean
	rm -rf $(BINS) $(UNIT_DUMPS) $(UNIT_ELFS)