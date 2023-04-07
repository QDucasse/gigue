import pytest
from unicorn.riscv_const import UC_RISCV_REG_RA, UC_RISCV_REG_T1

from gigue.helpers import bytes_to_int
from gigue.rimi.rimi_instructions import RIMIIInstruction, RIMISInstruction
from tests.conftest import ADDRESS
from tests.rimi.conftest import (
    D0_ADDRESS,
    D1_ADDRESS,
    DATA_D1_ADDRESS,
    RIMI_SHADOW_STACK_ADDRESS,
    TEST_DATA_REG_D1,
    UC_DATA_REG_D1,
    UC_RIMI_SHADOW_STACK_REG,
)

# ===================================
#        Disassembly Tests
# ===================================


@pytest.mark.parametrize(
    "name", ["ls", "lb1", "lbu1", "lh1", "lhu1", "lw1", "lwu1", "ld1"]
)
def test_capstone_rimi_loads(name, cap_disasm_custom_setup, rimi_disasm_setup):
    constr = getattr(RIMIIInstruction, name)
    instr = constr(rd=5, rs1=6, imm=0)
    bytes = instr.generate_bytes()
    mc = instr.generate()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    instr_disasm = next(cap_disasm.disasm(bytes, D1_ADDRESS))
    assert instr_disasm.mnemonic == "custom"
    # RIMI
    rimi_disasm = rimi_disasm_setup
    instr_info = rimi_disasm.get_instruction_info(mc)
    assert instr_info.name == name
    assert instr_info.opcode == rimi_disasm.extract_opcode(mc)
    assert instr_info.funct3 == rimi_disasm.extract_funct3(mc)
    assert instr_info.funct7 == rimi_disasm.extract_funct7(mc)


@pytest.mark.parametrize("name", ["ss", "sb1", "sh1", "sw1", "sd1"])
def test_capstone_rimi_stores(name, cap_disasm_custom_setup, rimi_disasm_setup):
    constr = getattr(RIMISInstruction, name)
    instr = constr(rs1=5, rs2=6, imm=0)
    bytes = instr.generate_bytes()
    mc = instr.generate()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    instr_disasm = next(cap_disasm.disasm(bytes, D1_ADDRESS))
    assert instr_disasm.mnemonic == "custom"
    # RIMI
    rimi_disasm = rimi_disasm_setup
    instr_info = rimi_disasm.get_instruction_info(mc)
    assert instr_info.name == name
    assert instr_info.opcode == rimi_disasm.extract_opcode(mc)
    assert instr_info.funct3 == rimi_disasm.extract_funct3(mc)


def test_capstone_rimi_change_domain_fw(cap_disasm_custom_setup, rimi_disasm_setup):
    constr = getattr(RIMIIInstruction, "chdom")
    instr = constr(rd=1, rs1=1, imm=0)
    bytes = instr.generate_bytes()
    mc = instr.generate()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    instr_disasm = next(cap_disasm.disasm(bytes, D1_ADDRESS))
    assert instr_disasm.mnemonic == "custom"
    # RIMI
    rimi_disasm = rimi_disasm_setup
    instr_info = rimi_disasm.get_instruction_info(mc)
    assert instr_info.name == "chdom"
    assert instr_info.opcode == rimi_disasm.extract_opcode(mc)
    assert instr_info.funct3 == rimi_disasm.extract_funct3(mc)


def test_capstone_rimi_change_domain_bw(cap_disasm_custom_setup, rimi_disasm_setup):
    constr = getattr(RIMIIInstruction, "retdom")
    instr = constr()
    bytes = instr.generate_bytes()
    mc = instr.generate()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    instr_disasm = next(cap_disasm.disasm(bytes, D1_ADDRESS))
    assert instr_disasm.mnemonic == "custom"
    # RIMI
    rimi_disasm = rimi_disasm_setup
    instr_info = rimi_disasm.get_instruction_info(mc)
    assert instr_info.name == "retdom"
    assert instr_info.opcode == rimi_disasm.extract_opcode(mc)
    assert instr_info.funct3 == rimi_disasm.extract_funct3(mc)


# ===================================
#         Execution Tests
# ===================================


@pytest.mark.parametrize(
    "name, expected",
    [
        ("lb1", 0xFFFFFFFFFFFFFFFF),
        ("lbu1", 0xFF),
        ("ld1", 0xFFFFFFFFFFFFFFFF),
        ("lh1", 0xFFFFFFFFFFFFFFFF),
        ("lhu1", 0xFFFF),
        ("lw1", 0xFFFFFFFFFFFFFFFF),
        ("lwu1", 0xFFFFFFFF),
    ],
)
def test_unicorn_rimi_loads(
    name, expected, cap_disasm_custom_setup, uc_emul_setup, rimi_handler_setup
):
    constr = getattr(RIMIIInstruction, name)
    instr = constr(rs1=TEST_DATA_REG_D1, rd=6, imm=0)
    bytes = instr.generate_bytes()
    # Handler
    rimi_handler = rimi_handler_setup
    rimi_handler.current_domain = 1
    # Emulation
    uc_emul = uc_emul_setup
    # rimi_handler.hook_tracer(uc_emul)
    rimi_handler.hook_handler_expected(uc_emul, name)
    uc_emul.reg_write(UC_DATA_REG_D1, DATA_D1_ADDRESS)
    uc_emul.reg_write(UC_RISCV_REG_T1, 0x0)
    uc_emul.mem_write(DATA_D1_ADDRESS, b"\xff\xff\xff\xff\xff\xff\xff\xff")
    uc_emul.mem_write(D1_ADDRESS, bytes)
    uc_emul.emu_start(D1_ADDRESS, D1_ADDRESS + 4)
    uc_emul.emu_stop()
    assert uc_emul.reg_read(UC_RISCV_REG_T1) == expected


@pytest.mark.parametrize(
    "name, expected",
    [
        ("sb1", b"\xff\x00\x00\x00\x00\x00\x00\x00"),
        ("sh1", b"\xff\xff\x00\x00\x00\x00\x00\x00"),
        ("sw1", b"\xff\xff\xff\xff\x00\x00\x00\x00"),
        ("sd1", b"\xff\xff\xff\xff\xff\xff\xff\xff"),
    ],
)
def test_unicorn_rimi_stores(
    name, expected, cap_disasm_custom_setup, uc_emul_setup, rimi_handler_setup
):
    constr = getattr(RIMISInstruction, name)
    instr = constr(rs1=TEST_DATA_REG_D1, rs2=6, imm=0)
    bytes = instr.generate_bytes()
    # Handler
    rimi_handler = rimi_handler_setup
    rimi_handler.current_domain = 1
    # Emulation
    uc_emul = uc_emul_setup
    # rimi_handler.hook_tracer(uc_emul)
    rimi_handler.hook_handler_expected(uc_emul, name)
    uc_emul.reg_write(UC_DATA_REG_D1, DATA_D1_ADDRESS)
    uc_emul.reg_write(UC_RISCV_REG_T1, 0xFFFFFFFFFFFFFFFF)
    uc_emul.mem_write(DATA_D1_ADDRESS, b"\x00\x00\x00\x00\x00\x00\x00\x00")
    uc_emul.mem_write(D1_ADDRESS, bytes)
    uc_emul.emu_start(D1_ADDRESS, D1_ADDRESS + 4)
    uc_emul.emu_stop()
    assert uc_emul.mem_read(DATA_D1_ADDRESS, 8) == expected


def test_unicorn_rimi_ls(rimi_handler_setup, uc_emul_setup):
    instr = RIMIIInstruction.ls(rd=1, rs1=1, imm=0)
    bytes = instr.generate_bytes()
    # Handler
    rimi_handler = rimi_handler_setup
    # Emulation
    uc_emul = uc_emul_setup
    rimi_handler.hook_handler_expected(uc_emul, "ls")
    # rimi_handler.hook_tracer(uc_emul)
    uc_emul.reg_write(UC_RIMI_SHADOW_STACK_REG, RIMI_SHADOW_STACK_ADDRESS)
    uc_emul.reg_write(UC_RISCV_REG_RA, 0x0)
    return_address = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
    uc_emul.mem_write(RIMI_SHADOW_STACK_ADDRESS, return_address)
    uc_emul.mem_write(D1_ADDRESS, bytes)
    uc_emul.emu_start(D1_ADDRESS, D1_ADDRESS + 4)
    uc_emul.emu_stop()
    assert uc_emul.reg_read(UC_RISCV_REG_RA) == bytes_to_int(return_address)


def test_unicorn_rimi_ss(rimi_handler_setup, cap_disasm_custom_setup, uc_emul_setup):
    instr = RIMISInstruction.ss(rs1=1, rs2=1, imm=0)
    bytes = instr.generate_bytes()
    # Handler
    rimi_handler = rimi_handler_setup
    # Emulation
    uc_emul = uc_emul_setup
    rimi_handler.hook_handler_expected(uc_emul, "ss")
    # rimi_handler.hook_tracer(uc_emul)
    uc_emul.reg_write(UC_RIMI_SHADOW_STACK_REG, RIMI_SHADOW_STACK_ADDRESS)
    return_address = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
    uc_emul.reg_write(UC_RISCV_REG_RA, bytes_to_int(return_address))
    uc_emul.mem_write(RIMI_SHADOW_STACK_ADDRESS, b"\x00\x00\x00\x00\x00\x00\x00\x00")
    uc_emul.mem_write(D1_ADDRESS, bytes)
    uc_emul.emu_start(D1_ADDRESS, D1_ADDRESS + 4)
    uc_emul.emu_stop()
    assert uc_emul.mem_read(RIMI_SHADOW_STACK_ADDRESS, 8) == return_address


@pytest.mark.parametrize("offset", [0x0, 0x1, 0x1F, 0x7FF])
def test_unicorn_rimi_chdom(
    offset, rimi_handler_setup, cap_disasm_custom_setup, uc_emul_setup
):
    instr = RIMIIInstruction.chdom(rd=1, rs1=1, imm=offset)
    bytes = instr.generate_bytes()
    # Handler
    rimi_handler = rimi_handler_setup
    assert rimi_handler.current_domain == 0
    # Emulation
    uc_emul = uc_emul_setup
    rimi_handler.hook_handler_expected(uc_emul, "chdom")
    rimi_handler.hook_instr_tracer(uc_emul)
    rimi_handler.hook_reg_tracer(uc_emul)
    # call is auipc,rd, offsetHi | jalr, rd, offsetLo(rd)
    # > load pc in ra
    uc_emul.reg_write(UC_RISCV_REG_RA, D1_ADDRESS)
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, D1_ADDRESS + offset)
    uc_emul.emu_stop()
    assert rimi_handler.current_domain == 1


def test_unicorn_rimi_retdom(
    rimi_handler_setup, cap_disasm_custom_setup, uc_emul_setup
):
    instr = RIMIIInstruction.retdom()
    bytes = instr.generate_bytes()
    # Handler
    rimi_handler = rimi_handler_setup
    rimi_handler.current_domain = 1
    # Emulation
    uc_emul = uc_emul_setup
    rimi_handler.hook_handler_expected(uc_emul, "retdom")
    rimi_handler.hook_reg_tracer(uc_emul)
    rimi_handler.hook_instr_tracer(uc_emul)
    uc_emul.reg_write(UC_RISCV_REG_RA, D0_ADDRESS + 0x1000)
    uc_emul.mem_write(D1_ADDRESS, bytes)
    uc_emul.emu_start(D1_ADDRESS, D0_ADDRESS + 0x1000)
    uc_emul.emu_stop()
    assert rimi_handler.current_domain == 0
