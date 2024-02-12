import logging
from typing import List

import pytest
from unicorn.riscv_const import UC_RISCV_REG_RA, UC_RISCV_REG_T1

from gigue.builder import InstructionBuilder
from gigue.constants import INSTRUCTION_WEIGHTS
from gigue.helpers import flatten_list
from gigue.method import Method
from gigue.pic import PIC
from tests.conftest import (
    ADDRESS,
    RET_ADDRESS,
    TEST_CALLER_SAVED_REG,
    TEST_DATA_REG,
    TEST_DATA_SIZE,
    cap_disasm_bytes,
)

logger = logging.getLogger("gigue")


@pytest.fixture
def default_builder_setup():
    return InstructionBuilder()


@pytest.fixture
def methods_setup(default_builder_setup):
    default_builder = default_builder_setup
    methods: List[Method] = []
    current_address: int = ADDRESS
    for _ in range(5):
        method = Method(
            address=current_address,
            body_size=20,
            call_number=0,
            builder=default_builder,
        )
        methods.append(method)
        current_address += method.total_size() * 4
    return methods


def pic_add_methods(pic, methods):
    for method in methods:
        method.address += pic.get_switch_size() * 4
        pic.add_method(method)


# =================================
#            Size Tests
# =================================


@pytest.mark.parametrize("case_nb", range(1, 5))
def test_switch_size(default_builder_setup, methods_setup, case_nb):
    pic = PIC(
        case_number=case_nb,
        address=ADDRESS,
        builder=default_builder_setup,
    )
    pic_add_methods(pic, methods_setup[:case_nb])
    pic.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    # (case_nb * nb_instruction + ret) * instruction size
    assert pic.get_switch_size() == case_nb * 3 + 1
    assert pic.get_switch_size() == len(flatten_list(pic.switch_instructions))


@pytest.mark.parametrize("case_nb", range(1, 5))
def test_total_size(default_builder_setup, methods_setup, case_nb):
    pic = PIC(
        case_number=case_nb,
        address=ADDRESS,
        builder=default_builder_setup,
    )
    pic_add_methods(pic, methods_setup[:case_nb])
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


@pytest.mark.parametrize("case_nb", range(1, 5))
def test_switch_instructions_adding(
    default_builder_setup,
    methods_setup,
    case_nb,
    disasm_setup,
):
    pic = PIC(
        case_number=case_nb,
        address=ADDRESS,
        builder=default_builder_setup,
    )
    pic_add_methods(pic, methods_setup[:case_nb])
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
        logger.debug(
            "{}: address {}/{} + offset {}/{} = {}/{} | method {}/{}".format(
                case_nb,
                current_address,
                hex(current_address),
                call_offset,
                hex(call_offset),
                current_address + call_offset,
                hex(current_address + call_offset),
                method.address,
                hex(method.address),
            )
        )
        assert current_address + call_offset == method.address


# =================================
#         Execution tests
# =================================


@pytest.mark.parametrize("case_nb", range(1, 5))
@pytest.mark.parametrize("hit_case", range(1, 5))
def test_disassembly_execution(
    default_builder_setup,
    methods_setup,
    case_nb,
    hit_case,
    cap_disasm_setup,
    uc_emul_full_setup,
    handler_setup,
):
    pic = PIC(
        case_number=case_nb,
        address=ADDRESS,
        hit_case_reg=6,
        cmp_reg=5,
        builder=default_builder_setup,
    )
    pic_add_methods(pic, methods_setup[:case_nb])
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
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    uc_emul.reg_write(UC_RISCV_REG_T1, hit_case)
    uc_emul.mem_write(ADDRESS, pic_bytes)
    # Start emulation
    uc_emul.emu_start(ADDRESS, RET_ADDRESS)
    uc_emul.emu_stop()


# TODO: Interpreter call > trampoline > pic > return trampoline > return
