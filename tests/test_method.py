import logging

import pytest
from unicorn.riscv_const import UC_RISCV_REG_RA

from gigue.builder import InstructionBuilder
from gigue.constants import DATA_REG, DATA_SIZE, INSTRUCTION_WEIGHTS
from gigue.exceptions import (
    CallNumberException,
    MutualCallException,
    RecursiveCallException,
)
from gigue.helpers import window
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
def callees_method_setup(default_builder_setup):
    default_builder = default_builder_setup
    callee1 = Method(
        address=ADDRESS + 0x100,
        body_size=2,
        call_number=0,
        builder=default_builder,
    )
    callee2 = Method(
        address=ADDRESS + 0x200,
        body_size=2,
        call_number=0,
        builder=default_builder,
    )
    callee3 = Method(
        address=ADDRESS + 0x300,
        body_size=2,
        call_number=0,
        builder=default_builder,
    )
    return [callee1, callee2, callee3]


@pytest.fixture
def callees_pic_setup(default_builder_setup):
    default_builder = default_builder_setup
    callee1 = PIC(
        address=ADDRESS + 0x100,
        case_number=2,
        builder=default_builder,
    )
    callee2 = PIC(
        address=ADDRESS + 0x200,
        case_number=2,
        builder=default_builder,
    )
    callee3 = PIC(
        address=ADDRESS + 0x300,
        case_number=2,
        builder=default_builder,
    )
    return [callee1, callee2, callee3]


# =================================
#             Method
# =================================


@pytest.mark.parametrize("call_size", [3, 6])
def test_initialization(call_size, default_builder_setup):
    method = Method(
        address=ADDRESS,
        body_size=30,
        call_number=5,
        call_size=call_size,
        builder=default_builder_setup,
    )
    assert method.body_size == 30
    assert method.address == ADDRESS
    assert method.call_number == 5
    assert method.call_size == call_size


def test_error_initialization(default_builder_setup):
    with pytest.raises(CallNumberException):
        Method(
            address=ADDRESS,
            body_size=10,
            call_number=5,
            call_size=3,
            builder=default_builder_setup,
        )


@pytest.mark.parametrize("used_s_regs", range(8))
@pytest.mark.parametrize("call_number", [0, 1])
@pytest.mark.parametrize("body_size", [10, 50])
def test_total_size(body_size, call_number, used_s_regs, default_builder_setup):
    method = Method(
        address=ADDRESS,
        body_size=body_size,
        call_number=call_number,
        builder=default_builder_setup,
        used_s_regs=used_s_regs,
    )
    # Check base computation
    assert method.prologue_size == used_s_regs + 1 + (0 if method.is_leaf else 1)
    assert method.epilogue_size == used_s_regs + 2 + (0 if method.is_leaf else 1)
    assert (
        method.total_size()
        == 2 * used_s_regs + 3 + (0 if method.is_leaf else 2) + body_size
    )
    # Check after generation
    method.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    method_bytes = method.generate_bytes()
    assert method.total_size() == len(method_bytes) // 4


def test_fill_with_nops(default_builder_setup, cap_disasm_setup):
    method = Method(
        address=ADDRESS, body_size=30, call_number=5, builder=default_builder_setup
    )
    method.fill_with_nops()
    bytes = method.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    for i in cap_disasm.disasm(bytes, ADDRESS):
        assert i.mnemonic == "nop"


@pytest.mark.parametrize("used_s_regs", [0, 5, 10])
@pytest.mark.parametrize("call_number", [0, 5, 10])
@pytest.mark.parametrize("call_size", [3, 6])
def test_instructions_filling(
    used_s_regs, call_number, call_size, default_builder_setup, cap_disasm_setup
):
    method = Method(
        address=ADDRESS,
        body_size=100,
        call_number=call_number,
        call_size=call_size,
        used_s_regs=used_s_regs,
        builder=default_builder_setup,
    )
    method.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    # instructions contain:
    #   method body
    #   + s_regs load/store + ra load/store if not leaf
    #   + stack sizing (allocation/retribution)
    #   + ret
    size_expected = (
        method.body_size
        + 2 * (method.used_s_regs + (1 if not method.is_leaf else 0))
        + 2
        + 1
    )
    assert method.total_size() == size_expected
    assert len(method.instructions) == size_expected
    assert len(method.generate()) == size_expected
    assert len(method.generate_bytes()) == size_expected * 4


# =================================
#         Call Patching
# =================================


# Errors
# \______


def test_check_recursive_call_exception(callees_method_setup, default_builder_setup):
    method = Method(
        address=ADDRESS, body_size=10, call_number=3, builder=default_builder_setup
    )
    callee1, callee2, _ = callees_method_setup
    for elt in [method, callee1, callee2]:
        elt.fill_with_instructions(
            registers=TEST_CALLER_SAVED_REG,
            data_reg=DATA_REG,
            data_size=DATA_SIZE,
            weights=INSTRUCTION_WEIGHTS,
        )
    with pytest.raises(RecursiveCallException):
        callee1.check_callees([callee1, callee2, method])
    with pytest.raises(RecursiveCallException):
        callee2.check_callees([callee1, callee2, method])
    with pytest.raises(RecursiveCallException):
        method.check_callees([callee1, callee2, method])


def test_check_call_number_exception(callees_method_setup, default_builder_setup):
    method = Method(
        address=ADDRESS,
        body_size=10,
        call_number=3,
        builder=default_builder_setup,
    )
    callee1, callee2, _ = callees_method_setup
    for elt in [method, callee1, callee2]:
        elt.fill_with_instructions(
            registers=TEST_CALLER_SAVED_REG,
            data_reg=DATA_REG,
            data_size=DATA_SIZE,
            weights=INSTRUCTION_WEIGHTS,
        )
    with pytest.raises(CallNumberException):
        method.check_callees([callee1, callee2])


def test_check_mutual_call_exception(default_builder_setup):
    method = Method(
        address=ADDRESS,
        body_size=3,
        call_number=1,
        builder=default_builder_setup,
    )
    callee = Method(
        address=ADDRESS + 0x100,
        body_size=3,
        call_number=1,
        builder=default_builder_setup,
    )
    for elt in [method, callee]:
        elt.fill_with_instructions(
            registers=TEST_CALLER_SAVED_REG,
            data_reg=DATA_REG,
            data_size=DATA_SIZE,
            weights=INSTRUCTION_WEIGHTS,
        )
    callee.patch_base_calls([method])
    with pytest.raises(MutualCallException):
        method.check_callees([callee])


# Base call patching
# \__________________


def test_patch_base_calls_methods(
    default_builder_setup, disasm_setup, callees_method_setup
):
    method = Method(
        address=ADDRESS,
        body_size=20,
        call_number=3,
        call_size=3,
        builder=default_builder_setup,
    )
    callee1, callee2, callee3 = callees_method_setup
    for elt in [method, callee1, callee2, callee3]:
        elt.fill_with_instructions(
            registers=TEST_CALLER_SAVED_REG,
            data_reg=DATA_REG,
            data_size=DATA_SIZE,
            weights=INSTRUCTION_WEIGHTS,
        )
    method.patch_base_calls([callee1, callee2, callee3])
    # Tests correct jump offsets
    mc_method = method.generate()
    body_mc = mc_method[method.prologue_size : method.prologue_size + method.body_size]
    callee_addresses = [callee1.address, callee2.address, callee3.address]
    disasm = disasm_setup
    for i, instr_list in enumerate(window(body_mc[:-1], 2)):
        if [disasm.get_instruction_name(instr) for instr in instr_list] == [
            "auipc",
            "jalr",
        ]:
            offset = disasm.extract_pc_relative_offset(instr_list)
            extracted_address = method.address + (i + method.prologue_size) * 4 + offset
            assert extracted_address in callee_addresses
            callee_addresses.remove(extracted_address)
    assert callee_addresses == []


def test_patch_base_calls_pics(
    default_builder_setup, disasm_setup, callees_pic_setup, cap_disasm_setup
):
    method = Method(
        address=ADDRESS,
        body_size=10,
        call_number=3,
        call_size=3,
        builder=default_builder_setup,
    )
    callee1, callee2, callee3 = callees_pic_setup
    for elt in [method, callee1, callee2, callee3]:
        # Note: PICs are empty without methods
        # but should not affect the call depth
        elt.fill_with_instructions(
            registers=TEST_CALLER_SAVED_REG,
            data_reg=DATA_REG,
            data_size=DATA_SIZE,
            weights=INSTRUCTION_WEIGHTS,
        )
    method.patch_base_calls([callee1, callee2, callee3])
    # Capstone disassembly
    bytes_method = method.generate_bytes()
    cap_disasm = cap_disasm_setup
    for _ in cap_disasm.disasm(bytes_method, ADDRESS):
        pass
    # Tests correct jump offsets
    mc_method = method.generate()
    body_mc = mc_method[method.prologue_size : method.prologue_size + method.body_size]
    callee_addresses = [callee1.address, callee2.address, callee3.address]
    disasm = disasm_setup
    for i, instr_list in enumerate(window(body_mc, 3)):
        if [disasm.get_instruction_name(instr) for instr in instr_list] == [
            "addi",
            "auipc",
            "jalr",
        ]:
            offset = disasm.extract_pc_relative_offset(instr_list[1:])
            extracted_address = (
                method.address + (i + 1 + method.prologue_size) * 4 + offset
            )
            assert extracted_address in callee_addresses
            callee_addresses.remove(extracted_address)
    assert callee_addresses == []


# =================================
#         Execution tests
# =================================

# Instruction filling
# \___________________


@pytest.mark.parametrize("execution_number", range(5))
@pytest.mark.parametrize(
    "weights",
    [
        [100, 0, 0, 0, 0, 0, 0],  # Only R Instructions
        [0, 100, 0, 0, 0, 0, 0],  # Only I Instructions
        [0, 0, 100, 0, 0, 0, 0],  # Only U Instructions
        [0, 0, 0, 100, 0, 0, 0],  # Only J Instructions
        [0, 0, 0, 0, 100, 0, 0],  # Only B Instructions
        [0, 0, 0, 0, 0, 100, 0],  # Only Stores
        [0, 0, 0, 0, 0, 0, 100],  # Only Loads
        INSTRUCTION_WEIGHTS,
    ],
)
def test_instructions_disassembly_execution_smoke(
    execution_number,
    default_builder_setup,
    weights,
    cap_disasm_setup,
    uc_emul_full_setup,
):
    method = Method(
        address=ADDRESS,
        body_size=100,
        call_number=3,
        builder=default_builder_setup,
    )
    method.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=weights,
    )
    bytes = method.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    cap_disasm_bytes(cap_disasm, bytes, ADDRESS)
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, RET_ADDRESS)
    uc_emul.emu_stop()


# Base call patching
# \__________________


@pytest.mark.parametrize("execution_number", range(30))
def test_patch_base_calls_disassembly_execution(
    execution_number,
    default_builder_setup,
    callees_method_setup,
    cap_disasm_setup,
    uc_emul_full_setup,
    handler_setup,
):
    method = Method(
        address=ADDRESS, body_size=10, call_number=3, builder=default_builder_setup
    )
    callee1, callee2, callee3 = callees_method_setup
    for elt in [method, callee1, callee2, callee3]:
        elt.fill_with_instructions(
            registers=TEST_CALLER_SAVED_REG,
            data_reg=DATA_REG,
            data_size=DATA_SIZE,
            weights=INSTRUCTION_WEIGHTS,
        )
    method.patch_base_calls([callee1, callee2, callee3])
    bytes_method = method.generate_bytes()
    bytes_callee1 = callee1.generate_bytes()
    bytes_callee2 = callee2.generate_bytes()
    bytes_callee3 = callee3.generate_bytes()
    # Capstone disassembler
    cap_disasm = cap_disasm_setup
    logger.debug("Main Method")
    cap_disasm_bytes(cap_disasm, bytes_method, method.address)
    logger.debug("Callee 1")
    cap_disasm_bytes(cap_disasm, bytes_callee1, callee1.address)
    logger.debug("Callee 2")
    cap_disasm_bytes(cap_disasm, bytes_callee2, callee2.address)
    logger.debug("Callee 3")
    cap_disasm_bytes(cap_disasm, bytes_callee3, callee3.address)
    # Handler
    handler = handler_setup
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes_method)
    uc_emul.mem_write(callee1.address, bytes_callee1)
    uc_emul.mem_write(callee2.address, bytes_callee2)
    uc_emul.mem_write(callee3.address, bytes_callee3)
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    # Start emulation
    handler.hook_instr_tracer(uc_emul)
    uc_emul.emu_start(ADDRESS, RET_ADDRESS)
    uc_emul.emu_stop()


# TODO: Interpreter call > trampoline > method > return trampoline > return
