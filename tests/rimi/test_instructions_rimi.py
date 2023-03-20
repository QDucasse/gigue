import pytest
from unicorn.riscv_const import UC_RISCV_REG_T1

from gigue.rimi.instructions import RIMIIInstruction, RIMIJInstruction, RIMISInstruction
from tests.conftest import ADDRESS, DATA_ADDRESS
from tests.rimi.conftest import TEST_DATA_REG_D1, UC_DATA_REG_D1


@pytest.mark.parametrize(
    "name", ["lws", "lb1", "lbu1", "lh1", "lhu1", "lw1", "lwu1", "ld1"]
)
def test_capstone_rimi_loads(name, cap_disasm_custom_setup, rimi_disasm_setup):
    constr = getattr(RIMIIInstruction, name)
    instr = constr(rd=5, rs1=6, imm=0)
    bytes = instr.generate_bytes()
    mc = instr.generate()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == "custom"
    # RIMI
    rimi_disasm = rimi_disasm_setup
    instr_info = rimi_disasm.get_instruction_info(mc)
    assert instr_info.name == name
    assert instr_info.opcode7 == rimi_disasm.extract_opcode7(mc)
    assert instr_info.opcode3 == rimi_disasm.extract_opcode3(mc)
    assert instr_info.top7 == rimi_disasm.extract_top7(mc)


@pytest.mark.parametrize("name", ["sws", "sb1", "sh1", "sw1", "sd1"])
def test_capstone_rimi_stores(name, cap_disasm_custom_setup, rimi_disasm_setup):
    constr = getattr(RIMISInstruction, name)
    instr = constr(rs1=5, rs2=6, imm=0)
    bytes = instr.generate_bytes()
    mc = instr.generate()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == "custom"
    # RIMI
    rimi_disasm = rimi_disasm_setup
    instr_info = rimi_disasm.get_instruction_info(mc)
    assert instr_info.name == name
    assert instr_info.opcode7 == rimi_disasm.extract_opcode7(mc)
    assert instr_info.opcode3 == rimi_disasm.extract_opcode3(mc)


def test_capstone_rimi_change_domain_fw(cap_disasm_custom_setup, rimi_disasm_setup):
    constr = getattr(RIMIJInstruction, "jalx")
    instr = constr(rd=1, imm=0)
    bytes = instr.generate_bytes()
    mc = instr.generate()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == "custom"
    # RIMI
    rimi_disasm = rimi_disasm_setup
    instr_info = rimi_disasm.get_instruction_info(mc)
    assert instr_info.name == "jalx"
    assert instr_info.opcode7 == rimi_disasm.extract_opcode7(mc)
    assert instr_info.opcode3 == rimi_disasm.extract_opcode3(mc)


def test_capstone_rimi_change_domain_bw(cap_disasm_custom_setup, rimi_disasm_setup):
    constr = getattr(RIMIIInstruction, "jalrx")
    instr = constr()
    bytes = instr.generate_bytes()
    mc = instr.generate()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == "custom"
    # RIMI
    rimi_disasm = rimi_disasm_setup
    instr_info = rimi_disasm.get_instruction_info(mc)
    assert instr_info.name == "jalrx"
    assert instr_info.opcode7 == rimi_disasm.extract_opcode7(mc)
    assert instr_info.opcode3 == rimi_disasm.extract_opcode3(mc)


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
    # Disassembly
    # cap_disasm = cap_disasm_custom_setup
    # instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    # print(
    #     "0x%x:\t%s\t%s"
    #     % (instr_disasm.address, instr_disasm.mnemonic, instr_disasm.op_str)
    # )
    # Handler
    rimi_handler = rimi_handler_setup
    # Emulation
    uc_emul = uc_emul_setup
    # rimi_handler.hook_tracer(uc_emul)
    rimi_handler.hook_handler_expected(uc_emul, name)
    uc_emul.reg_write(UC_DATA_REG_D1, DATA_ADDRESS)
    uc_emul.reg_write(UC_RISCV_REG_T1, 0x0)
    uc_emul.mem_write(DATA_ADDRESS, b"\xff\xff\xff\xff\xff\xff\xff\xff")
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, ADDRESS + 4)
    uc_emul.emu_stop()
    assert uc_emul.reg_read(UC_RISCV_REG_T1) == expected


def test_unicorn_rimi_stores():
    pass


def test_unicorn_rimi_lws():
    pass


def test_unicorn_rimi_sws():
    pass


def test_unicorn_rimi_jalx():
    pass


def test_unicorn_rimi_jalrx():
    pass
