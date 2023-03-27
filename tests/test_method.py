import pytest
from unicorn.riscv_const import UC_RISCV_REG_RA

from gigue.constants import DATA_REG, DATA_SIZE, INSTRUCTION_WEIGHTS
from gigue.exceptions import (
    CallNumberException,
    EmptySectionException,
    MutualCallException,
    RecursiveCallException,
)
from gigue.helpers import window
from gigue.method import Method
from gigue.pic import PIC
from tests.conftest import ADDRESS, RET_ADDRESS, TEST_CALLER_SAVED_REG

# =================================
#             Method
# =================================


def test_initialization():
    method = Method(address=0x7FFFFF, body_size=30, call_number=5)
    assert method.body_size == 30
    assert method.address == 0x7FFFFF
    assert method.call_number == 5


def test_error_initialization():
    with pytest.raises(CallNumberException):
        Method(
            address=0x7FFFFF,
            body_size=10,
            call_number=5,
        )


def test_error_total_size_while_empty():
    m = Method(address=0x7FFFFF, body_size=30, call_number=5)
    with pytest.raises(EmptySectionException):
        m.total_size()


def test_fill_with_nops(cap_disasm_setup):
    method = Method(address=0x7FFFFF, body_size=30, call_number=5)
    method.fill_with_nops()
    bytes = method.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    for i in cap_disasm.disasm(bytes, ADDRESS):
        assert i.mnemonic == "nop"


@pytest.mark.parametrize("execution_number", range(5))
@pytest.mark.parametrize("used_s_regs", [0, 5, 10])
@pytest.mark.parametrize("call_number", [0, 1, 2])
def test_instructions_filling(
    execution_number, used_s_regs, call_number, cap_disasm_setup
):
    method = Method(
        address=0x1000,
        body_size=10,
        call_number=call_number,
        used_s_regs=used_s_regs,
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


def test_patch_calls_methods(disasm_setup, cap_disasm_setup):
    method = Method(
        address=0x1000,
        body_size=10,
        call_number=3,
    )
    callee1 = Method(
        address=0x1100,
        body_size=2,
        call_number=0,
    )
    callee2 = Method(
        address=0x1200,
        body_size=2,
        call_number=0,
    )
    callee3 = Method(
        address=0x1300,
        body_size=2,
        call_number=0,
    )
    method.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    callee1.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    callee2.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    callee3.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    method.patch_calls([callee1, callee2, callee3])
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
            offset = disasm.extract_call_offset(instr_list)
            extracted_address = method.address + (i + method.prologue_size) * 4 + offset
            assert extracted_address in callee_addresses
            callee_addresses.remove(extracted_address)
    assert callee_addresses == []


def test_patch_calls_pics(disasm_setup, cap_disasm_setup):
    method = Method(
        address=0x1000,
        body_size=10,
        call_number=3,
    )
    callee1 = PIC(
        address=0x1100,
        case_number=2,
        method_max_size=2,
        method_max_call_number=0,
        method_max_call_depth=0,
    )
    callee2 = PIC(
        address=0x1200,
        case_number=2,
        method_max_size=2,
        method_max_call_number=0,
        method_max_call_depth=0,
    )
    callee3 = PIC(
        address=0x1300,
        case_number=2,
        method_max_size=2,
        method_max_call_number=0,
        method_max_call_depth=0,
    )
    method.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    callee1.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    callee2.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    callee3.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    method.patch_calls([callee1, callee2, callee3])
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
            offset = disasm.extract_call_offset(instr_list[1:])
            extracted_address = (
                method.address + (i + 1 + method.prologue_size) * 4 + offset
            )
            assert extracted_address in callee_addresses
            callee_addresses.remove(extracted_address)
    assert callee_addresses == []


def test_patch_calls_check_recursive_loop_call():
    method = Method(
        address=0x1000,
        body_size=10,
        call_number=3,
    )
    callee1 = Method(
        address=0x1100,
        body_size=2,
        call_number=0,
    )
    callee2 = Method(
        address=0x1200,
        body_size=2,
        call_number=0,
    )
    method.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    callee1.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    callee2.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    with pytest.raises(RecursiveCallException):
        callee1.patch_calls([callee1, callee2, method])
    with pytest.raises(RecursiveCallException):
        callee2.patch_calls([callee1, callee2, method])
    with pytest.raises(RecursiveCallException):
        method.patch_calls([callee1, callee2, method])


def test_patch_calls_check_mutual_loop_call():
    method = Method(
        address=0x1000,
        body_size=3,
        call_number=1,
    )
    callee = Method(
        address=0x1100,
        body_size=3,
        call_number=1,
    )
    method.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    callee.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    callee.patch_calls([method])
    with pytest.raises(MutualCallException):
        method.patch_calls([callee])


# =================================
#         Execution tests
# =================================


@pytest.mark.parametrize("execution_number", range(30))
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
    execution_number, weights, cap_disasm_setup, uc_emul_full_setup
):
    method = Method(
        address=0x1000,
        body_size=10,
        call_number=3,
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
    for _ in cap_disasm.disasm(bytes, ADDRESS):
        pass
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    uc_emul.mem_write(ADDRESS, bytes)
    # from conftest import instrument_execution
    # instrument_execution(uc_emul, ADDRESS)
    uc_emul.emu_start(ADDRESS, RET_ADDRESS)
    uc_emul.emu_stop()


@pytest.mark.parametrize("execution_number", range(30))
def test_patch_calls_disassembly_execution(
    execution_number,
    uc_emul_full_setup,
):
    method = Method(
        address=ADDRESS,
        body_size=10,
        call_number=3,
    )
    callee1 = Method(
        address=0x1100,
        body_size=2,
        call_number=0,
    )
    callee2 = Method(
        address=0x1200,
        body_size=2,
        call_number=0,
    )
    callee3 = Method(
        address=0x1300,
        body_size=2,
        call_number=0,
    )
    method.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    callee1.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    callee2.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    callee3.fill_with_instructions(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=DATA_REG,
        data_size=DATA_SIZE,
        weights=INSTRUCTION_WEIGHTS,
    )
    method.patch_calls([callee1, callee2, callee3])
    bytes_method = method.generate_bytes()
    bytes_callee1 = callee1.generate_bytes()
    bytes_callee2 = callee2.generate_bytes()
    bytes_callee3 = callee3.generate_bytes()
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes_method)
    uc_emul.mem_write(0x1100, bytes_callee1)
    uc_emul.mem_write(0x1200, bytes_callee2)
    uc_emul.mem_write(0x1300, bytes_callee3)
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    uc_emul.emu_start(ADDRESS, RET_ADDRESS)

    # from conftest import instrument_execution
    # instrument_execution(uc_emul, ADDRESS)
    uc_emul.emu_stop()
