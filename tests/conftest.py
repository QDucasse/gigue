import pytest
from capstone import CS_ARCH_RISCV
from capstone import CS_MODE_RISCV64
from capstone import Cs
from unicorn import Uc
from unicorn.riscv_const import UC_RISCV_REG_RA
from unicorn.riscv_const import UC_RISCV_REG_SP
from unicorn.unicorn_const import UC_ARCH_RISCV
from unicorn.unicorn_const import UC_MODE_RISCV64

from gigue.constants import CALLER_SAVED_REG
from gigue.disassembler import Disassembler
from gigue.instructions import IInstruction

ADDRESS = 0x1000
STACK_ADDRESS = 0x9000
RET_ADDRESS = 0xBEE0


@pytest.fixture
def disasm_setup():
    disassembler = Disassembler()
    return disassembler


@pytest.fixture
def cap_disasm_setup():
    cap_disasm = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
    return cap_disasm


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
        uc_emul.mem_write(addr, IInstruction.nop().generate_bytes())
    # Zero out registers
    for reg in CALLER_SAVED_REG:
        uc_emul.reg_write(reg, 0)
    # Write RET ADDRESS in RA
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    # Write STACK ADDRESS in SP
    uc_emul.reg_write(UC_RISCV_REG_SP, STACK_ADDRESS)
    return uc_emul
