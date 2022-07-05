import pytest
from capstone import CS_ARCH_RISCV
from capstone import CS_MODE_RISCV64
from capstone import Cs
from unicorn import Uc
from unicorn.riscv_const import UC_RISCV_REG_RA
from unicorn.riscv_const import UC_RISCV_REG_T1
from unicorn.unicorn_const import UC_ARCH_RISCV
from unicorn.unicorn_const import UC_MODE_RISCV64

from gigue.constants import CALLER_SAVED_REG
from gigue.disassembler import Disassembler
from gigue.instructions import IInstruction
from gigue.pic import PIC

# =================================
#            Constants
# =================================

ADDRESS = 0x1000
RET_ADDRESS = 0xB000

disassembler = Disassembler()
cap_disasm = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)


# =================================
#              PIC
# =================================


@pytest.mark.parametrize("case_nb", range(1, 10))
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
def test_method_adding(case_nb, method_max_size):
    pic = PIC(case_number=case_nb, address=ADDRESS,
              method_max_size=method_max_size, method_max_calls=10,
              hit_case_reg=6, cmp_reg=5, registers=CALLER_SAVED_REG)
    pic.add_case_methods()
    assert len(pic.methods) == case_nb
    for method in pic.methods:
        assert method.size <= method_max_size


@pytest.mark.parametrize("case_nb", range(1, 10))
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
def test_switch_instructions_adding(case_nb, method_max_size):
    pic = PIC(case_number=case_nb, address=ADDRESS,
              method_max_size=method_max_size, method_max_calls=10,
              hit_case_reg=6, cmp_reg=5, registers=CALLER_SAVED_REG)
    pic.add_case_methods()
    pic.add_switch_instructions()
    # for i in cap_disasm.disasm(bytes, ADDRESS):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    assert len(pic.switch_instructions) == case_nb + 1
    assert len([item for sublist in pic.switch_instructions for item in sublist]) * 4 == pic.get_switch_size()
    # (case_nb * nb_instruction + ret) * instruction size
    assert pic.get_switch_size() == (case_nb * 3 + 1) * 4
    for i, (case, method) in enumerate(zip(pic.switch_instructions[:-1], pic.methods)):
        current_address = ADDRESS + (i * 3) * 4
        call_offset = disassembler.extract_imm_j(case[2].generate())
        # print("{}: address {}/{} + offset {}/{} = {}/{} | method {}/{}".format(
        #     i, current_address, hex(current_address),
        #     call_offset, hex(call_offset),
        #     current_address + call_offset, hex(current_address + call_offset),
        #     method.address, hex(method.address)
        # ))
        assert current_address + call_offset == method.address


@pytest.mark.parametrize("case_nb", range(1, 10))
@pytest.mark.parametrize("hit_case", range(1, 10))
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
def test_disassembly_execution(case_nb, method_max_size, hit_case):
    pic = PIC(case_number=case_nb, address=ADDRESS,
              method_max_size=method_max_size, method_max_calls=10,
              hit_case_reg=6, cmp_reg=5, registers=CALLER_SAVED_REG)
    pic.add_case_methods()
    pic.add_switch_instructions()
    pic.generate()
    pic_bytes = pic.generate_bytes()
    cap_disasm.disasm(pic_bytes, ADDRESS)
    for i in cap_disasm.disasm(pic_bytes, ADDRESS):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    uc_emul = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
    uc_emul.mem_map(ADDRESS, 2 * 1024 * 1024)
    for addr in range(ADDRESS, RET_ADDRESS + 4, 4):
        uc_emul.mem_write(addr, IInstruction.nop().generate_bytes())
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    uc_emul.reg_write(UC_RISCV_REG_T1, hit_case)
    uc_emul.mem_write(ADDRESS, pic_bytes)
    uc_emul.emu_start(ADDRESS, RET_ADDRESS)
    uc_emul.emu_stop()
