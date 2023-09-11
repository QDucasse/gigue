import pytest
from unicorn.riscv_const import UC_RISCV_REG_T3

from gigue.constants import INSTRUCTIONS_INFO
from gigue.disassembler import Disassembler
from gigue.fixer.fixer_constants import FIXER_CMP_REG, FIXER_INSTRUCTIONS_INFO
from tests.conftest import Handler

# Note: FIXER uses a duplicated call stack stored in the coprocessor memory.
# To simulate this behavior, we use a software "register" for the handler to
# store values in.

TEST_FIXER_CMP_REG = FIXER_CMP_REG
assert FIXER_CMP_REG + 1 == UC_RISCV_REG_T3
UC_FIXER_CMP_REG = UC_RISCV_REG_T3


class FIXERHandler(Handler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.shadow_stack = []
        self.cfi_exception = 0

    def handle_cficall(self, uc_emul, pc, instr):
        fixer_reg = self.disasm.extract_rs1(instr)
        return_address = uc_emul.reg_read(fixer_reg + 1)
        # print(f"handling cficall, adding {hex(return_address)} to shadow stack")
        # Note: + 1 due to unicorn offset
        self.shadow_stack.append(return_address)

    def handle_cfiret(self, uc_emul, *args, **kwargs):
        return_address = self.shadow_stack.pop()
        # print(f"handling cfiret, popping {hex(return_address)} from shadow stack")
        uc_emul.reg_write(UC_FIXER_CMP_REG, return_address)

    def handle_ecall(self, uc_emul, *args, **kwargs):
        self.cfi_exception = 1
        uc_emul.emu_stop()


@pytest.fixture
def fixer_disasm_setup():
    # FIXME: Merging dicts with the FIXER info first
    disassembler = Disassembler(FIXER_INSTRUCTIONS_INFO | INSTRUCTIONS_INFO)
    return disassembler


@pytest.fixture
def fixer_handler_setup(fixer_disasm_setup):
    return FIXERHandler(fixer_disasm_setup)
