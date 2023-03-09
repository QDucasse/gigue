import logging

import pytest
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, Cs
from unicorn import Uc, UcError
from unicorn.riscv_const import (
    UC_RISCV_REG_PC,
    UC_RISCV_REG_RA,
    UC_RISCV_REG_SP,
    UC_RISCV_REG_T6,
)
from unicorn.unicorn_const import (
    UC_ARCH_RISCV,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_MODE_RISCV64,
)

from gigue.constants import CALLER_SAVED_REG, DATA_REG
from gigue.dataminer import Dataminer
from gigue.disassembler import Disassembler
from gigue.exceptions import UnknownInstructionException
from gigue.helpers import bytes_to_int
from gigue.instructions import IInstruction

ADDRESS = 0x1000
STACK_ADDRESS = 0x9000
DATA_ADDRESS = 0xE000
RET_ADDRESS = 0xBEE0

# Check for correct test data reg, config vs unicorn one
# Note: Unicorn's 0 is the code for invalid reg so everything is shifted!
# Warning: UC_DATA_REG should only be used in this file and the rest
#          should transparently use TEST_DATA_REG
TEST_DATA_REG = DATA_REG
assert TEST_DATA_REG + 1 == UC_RISCV_REG_T6
UC_DATA_REG = UC_RISCV_REG_T6

TEST_CALLER_SAVED_REG = [reg for reg in CALLER_SAVED_REG if reg != TEST_DATA_REG]
TEST_DATA_SIZE = 1024


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


# =================================
#         Unicorn setup
# =================================


@pytest.fixture
def uc_emul_setup():
    uc_emul = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
    uc_emul.mem_map(ADDRESS, 2 * 1024 * 1024)
    return uc_emul


@pytest.fixture
def uc_emul_full_setup(uc_emul_setup):
    uc_emul = uc_emul_setup
    # Fill memory with nops up to B000 by default
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

    def trace_code(self, uc_emul, address, *args, **kwargs):
        instr = bytes_to_int(uc_emul.mem_read(address, 4))
        print(f">>> Tracing instruction {hex(instr)} at {hex(address)}")

    def hook_handler(self, uc_emul):
        uc_emul.hook_add(UC_HOOK_INTR, self.handle_custom_instruction, user_data=None)

    def hook_handler_expected(self, uc_emul, expected):
        uc_emul.hook_add(
            UC_HOOK_INTR, self.handle_custom_instruction, user_data=expected
        )

    def hook_tracer(self, uc_emul):
        uc_emul.hook_add(UC_HOOK_CODE, self.trace_code)


# =================================
#           Instrumenters
# =================================


def instrument_execution(uc_emul, start_address, ret_address=RET_ADDRESS):
    previous_pc = start_address
    try:
        while True:
            uc_emul.emu_start(begin=previous_pc, until=0, timeout=0, count=1)
            pc = uc_emul.reg_read(UC_RISCV_REG_PC)
            print(f"PC:{hex(pc)}")
            ra = uc_emul.reg_read(UC_RISCV_REG_RA)
            print(f"RA:{hex(ra)}")
            print("____")
            previous_pc = pc
    except UcError:
        pc = uc_emul.reg_read(UC_RISCV_REG_PC)
        ra = uc_emul.reg_read(UC_RISCV_REG_RA)
        if pc == ra:
            assert True
            return
        print(f"Exception !!! PC:{hex(pc)}")
        assert False


def instrument_stack(uc_emul, start_address):
    previous_pc = start_address
    try:
        while True:
            uc_emul.emu_start(previous_pc, 0, 0, 1)
            sp = uc_emul.reg_read(UC_RISCV_REG_SP)
            print(f"SP:{hex(sp)}")
            pc = uc_emul.reg_read(UC_RISCV_REG_PC)
            previous_pc = pc
    except UcError:
        pc = uc_emul.reg_read(UC_RISCV_REG_PC)
        ra = uc_emul.reg_read(UC_RISCV_REG_RA)
        sp = uc_emul.reg_read(UC_RISCV_REG_SP)
        print(f"Exception !!! PC:{hex(pc)}, RA:{hex(ra)}, SP:{hex(sp)}")
        assert False


# =================================
#           Loggers
# =================================


def pytest_configure():
    """Disable the logs when testing"""
    logger = logging.getLogger("gigue")
    logger.setLevel(logging.ERROR)
