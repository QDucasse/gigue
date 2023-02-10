# Check for RISCV toolchain env variable
ifndef RISCV
$(error Please set environment variable RISCV to your installed toolchain location (i.e. /opt/riscv-rocket))
endif

# Directories
src_dir = resources/common
bin_dir = bin

# Specify flags
XLEN ?= 64
RISCV_PREFIX ?= $(RISCV)/bin/riscv$(XLEN)-unknown-elf-
RISCV_GCC ?= $(RISCV_PREFIX)gcc
RISCV_GCC_OPTS ?= -march=rv64gc -mabi=lp64d -DPREALLOCATE=1 -mcmodel=medany -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf
RISCV_LINK_OPTS ?= -static -nostdlib -nostartfiles -lm -lgcc -T $(src_dir)/test.ld
RISCV_OBJDUMP ?= $(RISCV_PREFIX)objdump --disassemble-all --disassemble-zeroes --section=.text --section=.text.startup --section=.text.init --section=.data

# Define sources
SRCS_C=$(wildcard $(src_dir)/*.c) 
SRCS_S=$(wildcard $(src_dir)/*.S)
OBJS=$(patsubst $(src_dir)/%.c,$(bin_dir)/%.o,$(SRCS_C)) $(patsubst $(src_dir)/%.S,$(bin_dir)/%.o,$(SRCS_S))

# Check info!
$(info SRCS_S is $(SRCS_S))
$(info SRCS_C is $(SRCS_C))
$(info OBJS is $(OBJS))

# Headers!
incs  += -I$(src_dir)

default: $(bin_dir)/out

dump: $(bin_dir)/out.dump $(bin_dir)/out.bin.dump

# Link all the object files!
$(bin_dir)/out: $(OBJS)
	$(RISCV_GCC) $(RISCV_LINK_OPTS) $^ -o $@

# the objcopy way, the issue with this method is that the labels are auto generated!
# $(bin_dir)/out.o: $(bin_dir)/out.bin
# 	$(RISCV_PREFIX)objcopy -I binary -O elf64-littleriscv -B riscv --rename-section .data=.text $^ $@

# Generate the object files
bin/%.o: $(src_dir)/%.c
	$(RISCV_GCC) $(incs) $(RISCV_GCC_OPTS) $< -c -o $@ 

bin/%.o: $(src_dir)/%.S
	$(RISCV_GCC) $(incs) $(RISCV_GCC_OPTS) $< -c -o $@ 

# Dumps
$(bin_dir)/out.dump: $(bin_dir)/out
	$(RISCV_OBJDUMP) $< > $@

$(bin_dir)/out.bin.dump: $(bin_dir)/out.bin
	$(RISCV_PREFIX)objcopy -I binary -O elf64-littleriscv -B riscv --rename-section .data=.text $^ $@.temp
	$(RISCV_OBJDUMP) $@.temp > $@
	rm $@.temp

DUMPS=$(wildcard $(bin_dir)/*.dump)
TEMPS=$(wildcard $(bin_dir)/*.temp)

.PHONY: clean

clean:
	rm -rf $(OBJS) $(DUMPS) $(TEMPS) $(bin_dir)/out