import pytest
from conftest import ADDRESS
from conftest import DATA_REG
from conftest import RET_ADDRESS
from unicorn.riscv_const import UC_RISCV_REG_RA

from gigue.constants import CALLER_SAVED_REG
from gigue.helpers import window
from gigue.method import Method
from gigue.pic import PIC

# =================================
#             Method
# =================================


def test_initialization():
    method = Method(
        address=0x7FFFFF, body_size=30, call_number=5, registers=[], data_reg=DATA_REG
    )
    assert method.body_size == 30
    assert method.address == 0x7FFFFF
    assert method.call_number == 5


def test_error_initialization():
    with pytest.raises(ValueError):
        Method(
            address=0x7FFFFF,
            body_size=10,
            call_number=5,
            registers=[],
            data_reg=DATA_REG,
        )


def test_fill_with_nops(cap_disasm_setup):
    method = Method(
        address=0x7FFFFF, body_size=30, call_number=5, registers=[], data_reg=DATA_REG
    )
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
        registers=CALLER_SAVED_REG,
        used_s_regs=used_s_regs,
        data_reg=DATA_REG,
    )
    method.fill_with_instructions()
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
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    callee1 = Method(
        address=0x1100,
        body_size=2,
        call_number=0,
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    callee2 = Method(
        address=0x1200,
        body_size=2,
        call_number=0,
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    callee3 = Method(
        address=0x1300,
        body_size=2,
        call_number=0,
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    method.fill_with_instructions()
    callee1.fill_with_instructions()
    callee2.fill_with_instructions()
    callee3.fill_with_instructions()
    method.patch_calls([callee1, callee2, callee3])
    # Capstone disassembly
    # bytes_method = method.generate_bytes()
    # cap_disasm = cap_disasm_setup
    # for i in cap_disasm.disasm(method.generate_bytes(), ADDRESS):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
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
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    callee1 = PIC(
        address=0x1100,
        case_number=2,
        method_max_size=2,
        method_max_call_number=0,
        method_max_call_depth=0,
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    callee2 = PIC(
        address=0x1200,
        case_number=2,
        method_max_size=2,
        method_max_call_number=0,
        method_max_call_depth=0,
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    callee3 = PIC(
        address=0x1300,
        case_number=2,
        method_max_size=2,
        method_max_call_number=0,
        method_max_call_depth=0,
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    method.fill_with_instructions()
    callee1.fill_with_instructions()
    callee2.fill_with_instructions()
    callee3.fill_with_instructions()
    method.patch_calls([callee1, callee2, callee3])
    # Capstone disassembly
    # bytes_method = method.generate_bytes()
    # cap_disasm = cap_disasm_setup
    # for i in cap_disasm.disasm(bytes_method, ADDRESS):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
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
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    callee1 = Method(
        address=0x1100,
        body_size=2,
        call_number=0,
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    callee2 = Method(
        address=0x1200,
        body_size=2,
        call_number=0,
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    method.fill_with_instructions()
    callee1.fill_with_instructions()
    callee2.fill_with_instructions()
    with pytest.raises(ValueError):
        callee1.patch_calls([callee1, callee2, method])
    with pytest.raises(ValueError):
        callee2.patch_calls([callee1, callee2, method])
    with pytest.raises(ValueError):
        method.patch_calls([callee1, callee2, method])


def test_patch_calls_check_mutual_loop_call():
    method = Method(
        address=0x1000,
        body_size=3,
        call_number=1,
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    callee = Method(
        address=0x1100,
        body_size=3,
        call_number=1,
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    method.fill_with_instructions()
    callee.fill_with_instructions()
    callee.patch_calls([method])
    with pytest.raises(ValueError):
        method.patch_calls([callee])


# =================================
#         Execution tests
# =================================


@pytest.mark.parametrize("execution_number", range(30))
@pytest.mark.parametrize(
    "weights",
    [
        [100, 0, 0, 0, 0],  # Only R Instructions
        [0, 100, 0, 0, 0],  # Only I Instructions
        [0, 0, 100, 0, 0],  # Only U Instructions
        [0, 0, 0, 100, 0],  # Only J Instructions
        [0, 0, 0, 0, 100],  # Only B Instructions
        [35, 40, 10, 5, 10],
    ],
)
def test_instructions_disassembly_execution_smoke(
    execution_number, weights, cap_disasm_setup, uc_emul_full_setup
):
    method = Method(
        address=0x1000,
        body_size=10,
        call_number=3,
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    method.fill_with_instructions(weights)
    bytes = method.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # for i in cap_disasm.disasm(bytes, ADDRESS):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, RET_ADDRESS)
    uc_emul.emu_stop()


@pytest.mark.parametrize("execution_number", range(30))
def test_patch_calls_disassembly_execution(
    execution_number, uc_emul_full_setup, cap_disasm_setup
):
    method = Method(
        address=ADDRESS,
        body_size=10,
        call_number=3,
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    callee1 = Method(
        address=0x1100,
        body_size=2,
        call_number=0,
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    callee2 = Method(
        address=0x1200,
        body_size=2,
        call_number=0,
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    callee3 = Method(
        address=0x1300,
        body_size=2,
        call_number=0,
        registers=CALLER_SAVED_REG,
        data_reg=DATA_REG,
    )
    method.fill_with_instructions()
    callee1.fill_with_instructions()
    callee2.fill_with_instructions()
    callee3.fill_with_instructions()
    method.patch_calls([callee1, callee2, callee3])
    bytes_method = method.generate_bytes()
    # Disassembly
    # cap_disasm = cap_disasm_setup
    # print("Method disassembly:")
    # for i in cap_disasm.disasm(bytes_method, ADDRESS):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    # print("C1 disassembly:")
    # for i in cap_disasm.disasm(callee1.generate_bytes(), callee1.address):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    # print("C2 disassembly:")
    # for i in cap_disasm.disasm(callee1.generate_bytes(), callee1.address):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    # print("C3 disassembly:")
    # for i in cap_disasm.disasm(callee1.generate_bytes(), callee1.address):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

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


if __name__ == "__main__":
    from capstone import CS_ARCH_RISCV
    from capstone import CS_MODE_RISCV64
    from capstone import Cs
    from unicorn import Uc
    from unicorn.unicorn_const import UC_ARCH_RISCV
    from unicorn.unicorn_const import UC_MODE_RISCV64

    from gigue.instructions import IInstruction

    cap_disasm = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
    method = Method(
        address=0x1000, body_size=32, call_number=3, registers=CALLER_SAVED_REG
    )
    callee1 = Method(
        address=0x1100, body_size=2, call_number=0, registers=CALLER_SAVED_REG
    )
    callee2 = Method(
        address=0x1200, body_size=2, call_number=0, registers=CALLER_SAVED_REG
    )
    callee3 = Method(
        address=0x1300, body_size=2, call_number=0, registers=CALLER_SAVED_REG
    )
    method.fill_with_instructions(weights=[35, 40, 10, 5, 10])
    method.patch_calls([callee1, callee2, callee3])
    bytes = method.generate_bytes()
    for i in cap_disasm.disasm(bytes, ADDRESS):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    uc_emul = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
    uc_emul.mem_map(ADDRESS, 2 * 1024 * 1024)
    # Fill memory with nops up to B000 by default
    for addr in range(ADDRESS, RET_ADDRESS + 4, 4):
        uc_emul.mem_write(addr, IInstruction.nop().generate_bytes())
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    # Zero out registers
    for reg in CALLER_SAVED_REG:
        uc_emul.reg_write(reg, 0)
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    for addr in range(ADDRESS, RET_ADDRESS + 4, 4):
        uc_emul.mem_write(addr, IInstruction.nop().generate_bytes())
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    uc_emul.mem_write(ADDRESS, bytes)
    # for i in cap_disasm.disasm(uc_emul.mem_read(ADDRESS, ADDRESS + 32), ADDRESS): # RET_ADDRESS - ADDRESS + 8
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    uc_emul.emu_start(ADDRESS, RET_ADDRESS)
    uc_emul.emu_stop()
