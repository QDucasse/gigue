import logging
import os
import random

import pytest
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, Cs
from unicorn import Uc
from unicorn.riscv_const import (
    UC_RISCV_REG_PC,
    UC_RISCV_REG_RA,
    UC_RISCV_REG_SP,
    UC_RISCV_REG_T1,
    UC_RISCV_REG_T6,
)
from unicorn.unicorn_const import (
    UC_ARCH_RISCV,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_MODE_RISCV64,
)

from gigue.constants import CALL_TMP_REG, CALLER_SAVED_REG, DATA_REG
from gigue.dataminer import Dataminer
from gigue.disassembler import Disassembler
from gigue.exceptions import UnknownInstructionException
from gigue.helpers import bytes_to_int
from gigue.instructions import IInstruction

# Seed for reproducibility
SEED = bytes_to_int(os.urandom(16))
# print(SEED)
# SEED = 248211043577579144151423267814312480480
random.seed(SEED)

# =================================
#   Disassembler/Capstone setup
# =================================


@pytest.fixture
def disasm_setup():
    disassembler = Disassembler()
    return disassembler


@pytest.fixture
def cap_disasm_setup():
    cap_disasm = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
    return cap_disasm


@pytest.fixture
def cap_disasm_custom_setup():
    cap_disasm = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
    # Enable skipdata to disassemble custom instructions
    cap_disasm.skipdata_setup = ("custom", disassemble_custom_callback, None)
    cap_disasm.skipdata = True
    return cap_disasm


def disassemble_custom_callback(buffer, size, offset, userdata):
    return 4


def cap_disasm_bytes(cap_disasm, bytes, address):
    print("capdisasm")
    for i in cap_disasm.disasm(bytes, address):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


# =================================
#         Unicorn setup
# =================================

# Address layout for tests
ADDRESS = 0x1000
STACK_ADDRESS = 0x1FFF0
DATA_ADDRESS = 0xE000

INTERPRETER_START_ADDRESS = 0x1000
JIT_START_ADDRESS = 0x3000
RET_ADDRESS = 0xFFFE

# Check for correct test data reg, config vs unicorn one
# Note: Unicorn's 0 is the code for invalid reg so everything is shifted!
# Warning: UC_DATA_REG should only be used in this file and the rest
#          should transparently use TEST_DATA_REG (apart from setting up unicorn)
TEST_DATA_REG = DATA_REG
assert TEST_DATA_REG + 1 == UC_RISCV_REG_T6
UC_DATA_REG = UC_RISCV_REG_T6

TEST_CALLER_SAVED_REG = [reg for reg in CALLER_SAVED_REG if reg != TEST_DATA_REG]
TEST_DATA_SIZE = 1024

# Check for correct test data reg, config vs unicorn one
# Note: Unicorn's 0 is the code for invalid reg so everything is shifted!
# Warning: UC_DATA_REG should only be used in this file and the rest should
#          transparently use TEST_CALL_TMP_REG (apart from setting up unicorn)
TEST_CALL_TMP_REG = CALL_TMP_REG
assert TEST_CALL_TMP_REG + 1 == UC_RISCV_REG_T1
UC_CALL_TMP_REG = UC_RISCV_REG_T1


@pytest.fixture
def uc_emul_setup():
    uc_emul = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
    uc_emul.mem_map(ADDRESS, 3 * 1024 * 1024)
    return uc_emul


@pytest.fixture
def uc_emul_full_setup(uc_emul_setup):
    uc_emul = uc_emul_setup
    # Fill memory with nops up to RET_ADDRESS by default
    for addr in range(ADDRESS, RET_ADDRESS + 4, 4):
        uc_emul.mem_write(addr, IInstruction.ebreak().generate_bytes())
    # Zero out registers
    for reg in TEST_CALLER_SAVED_REG:
        uc_emul.reg_write(reg, 0)
    # Write data address in data reg
    uc_emul.reg_write(UC_DATA_REG, DATA_ADDRESS)
    # Write data to memory
    miner = Dataminer()
    data_bytes = miner.generate_data("iterative32", TEST_DATA_SIZE)
    uc_emul.mem_write(DATA_ADDRESS, data_bytes)
    # Write RET ADDRESS in RA
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    # Write STACK ADDRESS in SP
    uc_emul.reg_write(UC_RISCV_REG_SP, STACK_ADDRESS)
    return uc_emul


def bin_info(binary, address):
    print(
        "---\n"
        f"Binary: from {hex(address)} to {hex(address + len(binary)) } (length"
        f" {len(binary)})"
        "\n---\n"
    )


class Handler:
    def __init__(self, disasm):
        self.disasm = disasm

    def handle_custom_instruction(self, uc_emul, intno, user_data):
        # When catching an exception, Unicorn already
        # forwarded the pc
        pc = uc_emul.reg_read(UC_RISCV_REG_PC) - 4
        instr = bytes_to_int(uc_emul.mem_read(pc, 4))
        try:
            # Extracts the instruction name
            instr_name = self.disasm.get_instruction_info(instr).name
            # Compare it to the one expected (if needed)
            if user_data:
                assert instr_name == user_data
            # Call the handler if it exists
            try:
                handler_method = getattr(self.__class__, "handle_" + instr_name)
                handler_method(self, uc_emul, pc, instr)
            except AttributeError as err:
                # Otherwise stop the simulation and raise an exception
                uc_emul.emu_stop()
                raise AttributeError(
                    "Custom instruction callback has not been defined."
                ) from err
        except UnknownInstructionException:
            # Otherwise stop the simulation and raise an exception
            uc_emul.emu_stop()
            raise
        # Update the PC if the instruction handling went correctly
        uc_emul.reg_write(UC_RISCV_REG_PC, pc + 4)

    # Tracing methods for instrumentation
    # \__________________________________

    def trace_instr(self, uc_emul, address, *args, **kwargs):
        instr = bytes_to_int(uc_emul.mem_read(address, 4))
        print(f">>> Tracing instruction {hex(instr)} at {hex(address)}")

    def trace_reg(self, uc_emul, *args, **kwargs):
        current_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
        current_sp = uc_emul.reg_read(UC_RISCV_REG_SP)
        current_ra = uc_emul.reg_read(UC_RISCV_REG_RA)
        print(
            f">>> Tracing registers PC:{hex(current_pc)}, SP:{hex(current_sp)},"
            f" RA:{hex(current_ra)}"
        )

    def trace_exception(self, uc_emul, intno, user_data):
        print(f">>> SEED {SEED}: Unicorn exception nb {intno}, tracing info")
        self.trace_reg(uc_emul)

    # Hook installers
    # \______________

    def hook_handler(self, uc_emul):
        uc_emul.hook_add(UC_HOOK_INTR, self.handle_custom_instruction, user_data=None)

    def hook_handler_expected(self, uc_emul, expected):
        uc_emul.hook_add(
            UC_HOOK_INTR, self.handle_custom_instruction, user_data=expected
        )

    def hook_instr_tracer(self, uc_emul):
        uc_emul.hook_add(UC_HOOK_CODE, self.trace_instr)

    def hook_reg_tracer(self, uc_emul):
        uc_emul.hook_add(UC_HOOK_CODE, self.trace_reg)

    def hook_exception_tracer(self, uc_emul):
        uc_emul.hook_add(UC_HOOK_INTR, self.trace_exception)


@pytest.fixture
def handler_setup(disasm_setup):
    return Handler(disasm_setup)


# =================================
#           Loggers
# =================================


def pytest_configure():
    """Disable the logs when testing"""
    logger = logging.getLogger("gigue")
    logger.setLevel(logging.ERROR)
