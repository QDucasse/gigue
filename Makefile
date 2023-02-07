
# Directories
src_dir = resources/common
bin_dir = bin

# Specify flags
XLEN ?= 64
RISCV_PREFIX ?= /opt/riscv-rocket/bin/riscv$(XLEN)-unknown-elf-
RISCV_GCC ?= $(RISCV_PREFIX)gcc
RISCV_GCC_OPTS ?= -march=rv64gc -mabi=lp64d -DPREALLOCATE=1 -mcmodel=medany -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf
RISCV_LINK_OPTS ?= -static -nostdlib -nostartfiles -lm -lgcc -T $(src_dir)/test.ld
RISCV_OBJDUMP ?= $(RISCV_PREFIX)objdump --disassemble-all --disassemble-zeroes --section=.text --section=.text.startup --section=.text.init --section=.data

# Define sources
SRCS_C=$(wildcard $(src_dir)/*.c) 
SRCS_S=$(wildcard $(src_dir)/*.S)
OBJS=$(patsubst $(src_dir)/%.c,$(bin_dir)/%.o,$(SRCS_C)) $(patsubst $(src_dir)/%.S,$(bin_dir)/%.o,$(SRCS_S)) $(bin_dir)/out.o

# Check info!
# $(info SRCS_S is $(SRCS_S))
# $(info SRCS_C is $(SRCS_C))
# $(info OBJS is $(OBJS))

# Headers!
incs  += -I$(src_dir)

default: $(bin_dir)/out $(bin_dir)/out.dis

$(bin_dir)/out.dump: $(bin_dir)/out
	$(RISCV_OBJDUMP) $< > $@

# Link all the object files!
$(bin_dir)/out: $(bin_dir)/out.o $(OBJS)
	$(RISCV_GCC) $(RISCV_LINK_OPTS) $^ -o $@

# Objcopy! (TODO: generate the ELF directly from Python)
$(bin_dir)/out.o: $(bin_dir)/out.bin
	$(RISCV_PREFIX)objcopy -I binary -O elf64-littleriscv -B riscv --rename-section .data=.text $^ $@

# Generate the object files
bin/%.o: $(src_dir)/%.c
	$(RISCV_GCC) $(incs) $(RISCV_GCC_OPTS) $< -c -o $@ 

bin/%.o: $(src_dir)/%.S
	$(RISCV_GCC) $(incs) $(RISCV_GCC_OPTS) $< -c -o $@ 

.PHONY: clean

clean:
	rm -rf $(OBJS)