import pytest
from unicorn.riscv_const import UC_RISCV_REG_T3

from gigue.constants import INSTRUCTIONS_INFO
from gigue.disassembler import Disassembler
from gigue.fixer.constants import FIXER_CMP_REG, FIXER_INSTRUCTIONS_INFO
from tests.conftest import Handler

# Note: FIXER uses a duplicated call stack stored in the coprocessor memory.
# To simulate this behavior, we use a software "register" for the handler to
# store values in.

assert FIXER_CMP_REG + 1 == UC_RISCV_REG_T3
UC_FIXER_CMP_REG = UC_RISCV_REG_T3


class FIXERHandler(Handler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.shadow_stack = []

    def handle_cficall(self, uc_emul):
        return_addr = uc_emul.reg_read(UC_FIXER_CMP_REG)
        self.shadow_stack.append(return_addr)

    def handle_cfiret(self, uc_emul):
        uc_emul.reg_write(UC_FIXER_CMP_REG, self.shadow_stack.pop())


@pytest.fixture
def fixer_disasm_setup():
    disassembler = Disassembler(INSTRUCTIONS_INFO | FIXER_INSTRUCTIONS_INFO)
    return disassembler


@pytest.fixture
def fixer_handler_setup(fixer_disasm_setup):
    return FIXERHandler(fixer_disasm_setup)
