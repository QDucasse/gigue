import pytest
from unicorn.riscv_const import UC_RISCV_REG_RA, UC_RISCV_REG_T1

from gigue.builder import InstructionBuilder
from gigue.constants import INSTRUCTION_WEIGHTS
from gigue.helpers import flatten_list
from gigue.pic import PIC
from gigue.trampoline import Trampoline
from tests.conftest import (
    ADDRESS,
    RET_ADDRESS,
    TEST_CALLER_SAVED_REG,
    TEST_DATA_REG,
    TEST_DATA_SIZE,
    cap_disasm_bytes,
)


@pytest.fixture
def default_builder_setup():
    return InstructionBuilder()


# =================================
#            Size Tests
# =================================


@pytest.mark.parametrize("case_nb", range(1, 10))
@pytest.mark.parametrize("method_size", [20, 50, 100, 200])
def test_switch_size(default_builder_setup, case_nb, method_size):
    pic = PIC(
        case_number=case_nb,
        address=ADDRESS,
        method_size=method_size,
        method_variation_mean=0.2,
        method_variation_stdev=0.1,
        method_call_occupation_mean=0.2,
        method_call_occupation_stdev=0.1,
        method_call_depth_mean=2,
        builder=default_builder_setup,
    )
    pic.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    # (case_nb * nb_instruction + ret) * instruction size
    assert pic.get_switch_size() == case_nb * 3 + 1
    assert pic.get_switch_size() == len(flatten_list(pic.switch_instructions))


@pytest.mark.parametrize("case_nb", range(1, 10))
@pytest.mark.parametrize("method_size", [20, 50, 100, 200])
def test_total_size(default_builder_setup, case_nb, method_size):
    pic = PIC(
        case_number=case_nb,
        address=ADDRESS,
        method_size=method_size,
        method_variation_mean=0.2,
        method_variation_stdev=0.1,
        method_call_occupation_mean=0.2,
        method_call_occupation_stdev=0.1,
        method_call_depth_mean=2,
        builder=default_builder_setup,
    )
    pic.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    assert pic.total_size() == pic.get_switch_size() + len(
        flatten_list([method.generate() for method in pic.methods])
    )
    assert pic.total_size() == len(pic.generate_bytes()) // 4


# =================================
#    Instruction Filling Tests
# =================================


@pytest.mark.parametrize("case_nb", range(1, 10))
@pytest.mark.parametrize("method_size", [20, 50, 100, 200])
def test_method_adding(default_builder_setup, case_nb, method_size):
    method_variation_mean = 0.2
    method_variation_stdev = 0.1
    pic = PIC(
        case_number=case_nb,
        address=ADDRESS,
        method_size=method_size,
        method_variation_mean=method_variation_mean,
        method_variation_stdev=method_variation_stdev,
        method_call_occupation_mean=0.2,
        method_call_occupation_stdev=0.1,
        method_call_depth_mean=2,
        builder=default_builder_setup,
    )
    pic.add_case_methods(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    assert len(pic.methods) == case_nb
    for method in pic.methods:
        max_deviation = method_variation_mean + 4 * method_variation_stdev
        assert (
            method_size * (1 - max_deviation)
            <= method.body_size
            <= method_size * (1 + max_deviation)
        )


@pytest.mark.parametrize("case_nb", range(1, 10))
@pytest.mark.parametrize("method_size", [5, 20, 50, 100, 200])
def test_switch_instructions_adding(
    default_builder_setup, case_nb, method_size, disasm_setup, cap_disasm_setup
):
    pic = PIC(
        case_number=case_nb,
        address=ADDRESS,
        method_size=method_size,
        method_variation_mean=0.2,
        method_variation_stdev=0.1,
        method_call_occupation_mean=0.2,
        method_call_occupation_stdev=0.1,
        method_call_depth_mean=2,
        builder=default_builder_setup,
    )
    pic.add_case_methods(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    pic.add_switch_instructions()
    # Switch instructions should hold the different switch cases and a final ret
    assert len(pic.switch_instructions) == case_nb + 1
    assert len(flatten_list(pic.switch_instructions)) == pic.get_switch_size()
    # Disassembly
    disasm = disasm_setup
    for case_nb, (case, method) in enumerate(
        zip(pic.switch_instructions[:-1], pic.methods)
    ):
        current_address = ADDRESS + (case_nb * 3 + 2) * 4
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
@pytest.mark.parametrize("method_size", [20, 50, 100, 200])
def test_disassembly_execution(
    default_builder_setup,
    case_nb,
    method_size,
    hit_case,
    cap_disasm_setup,
    uc_emul_full_setup,
    handler_setup,
):
    pic = PIC(
        case_number=case_nb,
        address=ADDRESS,
        method_size=method_size,
        method_variation_mean=0.2,
        method_variation_stdev=0.1,
        method_call_occupation_mean=0.2,
        method_call_occupation_stdev=0.1,
        method_call_depth_mean=2,
        hit_case_reg=6,
        cmp_reg=5,
        builder=default_builder_setup,
    )
    pic.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    pic.generate()
    pic_bytes = pic.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    cap_disasm_bytes(cap_disasm, pic_bytes, ADDRESS)
    # Handler
    handler = handler_setup
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    uc_emul.reg_write(UC_RISCV_REG_T1, hit_case)
    uc_emul.mem_write(ADDRESS, pic_bytes)
    # Start emulation
    handler.hook_instr_tracer(uc_emul)
    uc_emul.emu_start(ADDRESS, RET_ADDRESS)
    uc_emul.emu_stop()


@pytest.mark.parametrize("case_nb", range(1, 5))
@pytest.mark.parametrize("hit_case", range(1, 5))
@pytest.mark.parametrize("method_size", [20, 50, 100, 200])
def test_trampoline_disassembly_execution(
    default_builder_setup,
    case_nb,
    method_size,
    hit_case,
    cap_disasm_setup,
    uc_emul_full_setup,
    handler_setup,
):
    call_tramp = Trampoline(
        name="call_jit_elt", address=ADDRESS, builder=default_builder_setup
    )
    call_instrs = call_tramp.build()
    ret_tramp = Trampoline(
        name="ret_from_jit_elt",
        address=ADDRESS + len(call_instrs) * 4,
        builder=default_builder_setup,
    )
    ret_instrs = ret_tramp.build()
    bytes_call_tramp = call_tramp.generate_bytes()
    bytes_ret_tramp = ret_tramp.generate_bytes()
    CODE_ADDRESS = ADDRESS + (len(call_instrs) + len(ret_instrs)) * 4
    pic = PIC(
        case_number=case_nb,
        address=CODE_ADDRESS,
        method_size=method_size,
        method_variation_mean=0.2,
        method_variation_stdev=0.1,
        method_call_occupation_mean=0.2,
        method_call_occupation_stdev=0.1,
        method_call_depth_mean=2,
        hit_case_reg=6,
        cmp_reg=5,
        builder=default_builder_setup,
    )
    pic.fill_with_trampoline_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
        ret_trampoline_offset=ret_tramp.address - pic.address,
    )
    pic.generate()
    pic_bytes = pic.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    cap_disasm_bytes(cap_disasm, pic_bytes, ADDRESS)
    # Handler
    handler = handler_setup
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(call_tramp.address, bytes_call_tramp)
    uc_emul.mem_write(ret_tramp.address, bytes_ret_tramp)
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    uc_emul.reg_write(UC_RISCV_REG_T1, hit_case)
    uc_emul.mem_write(CODE_ADDRESS, pic_bytes)
    # Start emulation
    # Should do PIC --run through switch--> method
    #           --ret--> PIC --ret-->
    handler.hook_instr_tracer(uc_emul)
    uc_emul.emu_start(CODE_ADDRESS, RET_ADDRESS)
    uc_emul.emu_stop()
