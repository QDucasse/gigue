import pytest
from unicorn.riscv_const import UC_RISCV_REG_RA, UC_RISCV_REG_T6

from gigue.constants import INSTRUCTIONS_INFO
from gigue.disassembler import Disassembler
from gigue.helpers import int_to_bytes64
from gigue.rimi.constants import RIMI_INSTRUCTIONS_INFO, RIMI_SHADOW_STACK_REG
from tests.conftest import Handler

# Note: FIXER uses a duplicated call stack stored in the coprocessor memory.
# To simulate this behavior, we use a software "register" for the handler to
# store values in.

assert RIMI_SHADOW_STACK_REG + 1 == UC_RISCV_REG_T6
UC_RIMI_SHADOW_STACK_REG = UC_RISCV_REG_T6

RIMI_SHADOW_STACK_ADDRESS = 0x5000


class RIMIHandler(Handler):
    # Shadow stack instructions
    # \________________________

    def handle_sws(self, uc_emul):
        ss_address = uc_emul.reg_read(UC_RIMI_SHADOW_STACK_REG)
        return_address = uc_emul.reg_read(UC_RISCV_REG_RA)
        uc_emul.mem_write(ss_address, int_to_bytes64(return_address))

    def handle_lws(self, uc_emul):
        ss_address = uc_emul.reg_read(UC_RIMI_SHADOW_STACK_REG)
        return_address = uc_emul.mem_read(ss_address, 8)
        uc_emul.reg_write(UC_RISCV_REG_RA, return_address)

    # Load duplicate instructions
    # \__________________________

    def handle_lb1(self, uc_emul):
        pass

    def handle_lbu1(self, uc_emul):
        pass

    def handle_lh1(self, uc_emul):
        pass

    def handle_lhu1(self, uc_emul):
        pass

    def handle_lw1(self, uc_emul):
        pass

    def handle_lwu1(self, uc_emul):
        pass

    def handle_ld1(self, uc_emul):
        pass

    # Store duplicate instructions
    # \___________________________

    def handle_sb1(self, uc_emul):
        pass

    def handle_sh1(self, uc_emul):
        pass

    def handle_sw1(self, uc_emul):
        pass

    def handle_sd1(self, uc_emul):
        pass

    # Domain change instructions
    # \_________________________

    def handle_jalx(self, uc_emul):
        pass

    def handle_jalrx(self, uc_emul):
        pass


@pytest.fixture
def rimi_disasm_setup():
    disassembler = Disassembler(INSTRUCTIONS_INFO | RIMI_INSTRUCTIONS_INFO)
    return disassembler


@pytest.fixture
def rimi_handler_setup(rimi_disasm_setup):
    return RIMIHandler(rimi_disasm_setup)
