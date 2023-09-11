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

# Emulator info
MAX_CYCLES ?= 100000000

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

exec: $(bin_dir)/out.corelog

# Link all the object files!
$(bin_dir)/out.elf: $(OBJS)
	$(RISCV_GCC) $(RISCV_LINK_OPTS) $(OBJS) -o $@

# the objcopy way, the issue with this method is that the labels are auto generated!
# $(bin_dir)/out.o: $(bin_dir)/out.bin
# 	$(RISCV_PREFIX)objcopy -I binary -O elf64-littleriscv -B riscv --rename-section .data=.text $^ $@

# Generate the object files
$(bin_dir)/%.o: $(src_dir)/%.c
	$(RISCV_GCC) $(incs) $(RISCV_GCC_OPTS) $< -c -o $@ 

$(bin_dir)/%.o: $(src_dir)/%.S
	$(RISCV_GCC) $(incs) $(RISCV_GCC_OPTS) $< -c -o $@ 

$(bin_dir)/template.o: $(template_dir)/$(TEMPLATE).S $(bin_dir)/int.bin $(bin_dir)/jit.bin
	$(RISCV_GCC) $(incs) $(RISCV_GCC_OPTS) $< -c -o $@ 

# Dumps
$(bin_dir)/out.dump: $(bin_dir)/out.elf
	$(RISCV_OBJDUMP) $< > $@

$(bin_dir)/%.bin.dump: $(bin_dir)/%.bin
	$(RISCV_PREFIX)objcopy -I binary -O elf64-littleriscv -B riscv --rename-section .data=.text $^ $@.temp
	$(RISCV_OBJDUMP) $@.temp > $@
	rm $@.temp

# Verilator execution
$(bin_dir)/out.corelog: $(bin_dir)/out.elf
ifndef EMULATOR
$(error Please set environment variable EMULATOR to the (compiled) verilator emulator of your core)
endif
	$(EMULATOR) +max-cycles=$(MAX_CYCLES) +verbose $< 3>&1 1>&2 2>&3 | $(RISCV)/bin/spike-dasm > $@


# Unit tests
unitdump: $(bin_dir)/unit.dump

$(bin_dir)/unit.elf: $(UNIT_OBJS)
	$(RISCV_GCC) $(RISCV_LINK_OPTS) $(UNIT_OBJS) -o $@

$(bin_dir)/unittemplate.o: $(template_dir)/$(TEMPLATE).S $(bin_dir)/unit.bin
	$(RISCV_GCC) $(incs) $(RISCV_GCC_OPTS) $< -c -o $@ 

$(bin_dir)/unit.dump: $(bin_dir)/unit.elf
	$(RISCV_OBJDUMP) $< > $@

# Aliases for cleanup
DUMPS=$(wildcard $(bin_dir)/*.dump)
BINS=$(wildcard $(bin_dir)/*.bin)
TEMPS=$(wildcard $(bin_dir)/*.temp)
ELFS=$(wildcard $(bin_dir)/*.elf)
CORE_LOGS=$(wildcard $(bin_dir)/*.core)
WAVEFORMS=$(wildcard $(bin_dir)/*.vcd)
UNIT_DUMPS=$(wildcard $(bin_dir)/unit/*.dump)
UNIT_ELFS=$(wildcard $(bin_dir)/unit/*.elf)

.PHONY: clean

clean:
	rm -rf $(ELFS) $(OBJS) $(UNIT_OBJS) $(DUMPS) $(TEMPS) $(CORE_LOGS) $(WAVEFORMS)

cleanall: clean
	rm -rf $(BINS) $(UNIT_DUMPS) $(UNIT_ELFS)