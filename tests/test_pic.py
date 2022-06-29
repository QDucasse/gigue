import pytest
from capstone import CS_ARCH_RISCV
from capstone import CS_MODE_RISCV64
from capstone import Cs
from unicorn import Uc
from unicorn.riscv_const import UC_RISCV_REG_RA
from unicorn.unicorn_const import UC_ARCH_RISCV
from unicorn.unicorn_const import UC_MODE_RISCV64

from gigue.constants import CALLER_SAVED_REG
from gigue.instructions import IInstruction
from gigue.pic import PIC

# =================================
#            Constants
# =================================

ADDRESS = 0x1000
RET_ADDRESS = 0xB000

cap_disasm = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
uc_emul = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
uc_emul.mem_map(ADDRESS, 2 * 1024 * 1024)
# Fill memory with nops up to BEEC by default
for addr in range(ADDRESS, RET_ADDRESS + 4, 4):
    uc_emul.mem_write(addr, IInstruction.nop().generate_bytes())
uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)


def setup_function():
    # Zero out registers
    for reg in CALLER_SAVED_REG:
        uc_emul.reg_write(reg, 0)
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)


# =================================
#              PIC
# =================================


@pytest.mark.parametrize("case_nb", range(10))
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
def test_method_adding(case_nb, method_max_size):
    pic = PIC(case_number=case_nb, address=ADDRESS,
              method_max_size=method_max_size, method_max_calls=10,
              temp_reg=6, registers=CALLER_SAVED_REG)
    pic.add_case_methods()
    assert len(pic.methods) == case_nb
    for method in pic.methods:
        assert method.size <= method_max_size


@pytest.mark.parametrize("case_nb", range(10))
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
def test_switch_instructions_adding(case_nb, method_max_size):
    pic = PIC(case_number=case_nb, address=ADDRESS,
              method_max_size=method_max_size, method_max_calls=10,
              temp_reg=6, registers=CALLER_SAVED_REG)
    pic.add_case_methods()
    pic.add_switch_instructions()
    assert len(pic.switch_instructions) == case_nb + 1
    # assert len(pic.switch_instructions) == pic.get_switch_size()
    # for case in self.switch_instructions:
    #     pass
