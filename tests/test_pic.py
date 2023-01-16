import pytest
from conftest import ADDRESS
from conftest import RET_ADDRESS
from unicorn.riscv_const import UC_RISCV_REG_RA
from unicorn.riscv_const import UC_RISCV_REG_T1

from gigue.constants import CALLER_SAVED_REG
from gigue.helpers import flatten_list
from gigue.pic import PIC

# =================================
#            Size Tests
# =================================


@pytest.mark.parametrize("case_nb", range(1, 10))
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
def test_switch_size(case_nb, method_max_size):
    pic = PIC(
        case_number=case_nb,
        address=ADDRESS,
        method_max_size=method_max_size,
        method_max_call_number=5,
        method_max_call_depth=5,
        registers=CALLER_SAVED_REG,
    )
    pic.add_case_methods()
    pic.add_switch_instructions()
    # (case_nb * nb_instruction + ret) * instruction size
    assert pic.get_switch_size() == case_nb * 3 + 1
    assert pic.get_switch_size() == len(flatten_list(pic.switch_instructions))


@pytest.mark.parametrize("case_nb", range(1, 10))
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
def test_total_size(case_nb, method_max_size):
    pic = PIC(
        case_number=case_nb,
        address=ADDRESS,
        method_max_size=method_max_size,
        method_max_call_number=5,
        method_max_call_depth=5,
        registers=CALLER_SAVED_REG,
    )
    pic.add_case_methods()
    pic.add_switch_instructions()
    assert pic.total_size() == pic.get_switch_size() + len(
        flatten_list([method.generate() for method in pic.methods])
    )
    assert pic.total_size() == len(pic.generate_bytes()) // 4


# =================================
#    Instruction Filling Tests
# =================================


@pytest.mark.parametrize("case_nb", range(1, 10))
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
def test_method_adding(case_nb, method_max_size):
    pic = PIC(
        case_number=case_nb,
        address=ADDRESS,
        method_max_size=method_max_size,
        method_max_call_number=5,
        method_max_call_depth=5,
        registers=CALLER_SAVED_REG,
    )
    pic.add_case_methods()
    assert len(pic.methods) == case_nb
    for method in pic.methods:
        assert method.body_size <= method_max_size


@pytest.mark.parametrize("case_nb", range(1, 10))
@pytest.mark.parametrize("method_max_size", [5, 20, 50, 100, 200])
def test_switch_instructions_adding(
    case_nb, method_max_size, disasm_setup, cap_disasm_setup
):
    pic = PIC(
        case_number=case_nb,
        address=ADDRESS,
        method_max_size=method_max_size,
        method_max_call_number=5,
        method_max_call_depth=5,
        registers=CALLER_SAVED_REG,
    )
    pic.add_case_methods()
    pic.add_switch_instructions()
    # bytes = pic.generate_bytes()
    # cap_disasm = cap_disasm_setup
    # for i in cap_disasm.disasm(bytes, ADDRESS):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    # Switch instructions should hold the different switch cases and a final ret
    assert len(pic.switch_instructions) == case_nb + 1
    assert len(flatten_list(pic.switch_instructions)) == pic.get_switch_size()
    # Disassembly
    disasm = disasm_setup
    for i, (case, method) in enumerate(zip(pic.switch_instructions[:-1], pic.methods)):
        current_address = ADDRESS + ((i + 1) * 3) * 4
        call_offset = disasm.extract_imm_j(case[2].generate())
        # print("{}: address {}/{} + offset {}/{} = {}/{} | method {}/{}".format(
        #     i, current_address, hex(current_address),
        #     call_offset, hex(call_offset),
        #     current_address + call_offset, hex(current_address + call_offset),
        #     method.address, hex(method.address)
        # ))
        assert current_address + call_offset == method.address


# =================================
#         Execution tests
# =================================


@pytest.mark.parametrize("case_nb", range(1, 5))
@pytest.mark.parametrize("hit_case", range(1, 5))
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
def test_disassembly_execution(
    case_nb, method_max_size, hit_case, cap_disasm_setup, uc_emul_full_setup
):
    pic = PIC(
        case_number=case_nb,
        address=ADDRESS,
        method_max_size=method_max_size,
        method_max_call_number=5,
        method_max_call_depth=5,
        hit_case_reg=6,
        cmp_reg=5,
        registers=CALLER_SAVED_REG,
    )
    pic.add_case_methods()
    pic.add_switch_instructions()
    pic.generate()
    pic_bytes = pic.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    cap_disasm.disasm(pic_bytes, ADDRESS)
    # for i in cap_disasm.disasm(pic_bytes, ADDRESS):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    uc_emul.reg_write(UC_RISCV_REG_T1, hit_case)
    uc_emul.mem_write(ADDRESS, pic_bytes)
    uc_emul.emu_start(ADDRESS, RET_ADDRESS)
    uc_emul.emu_stop()
