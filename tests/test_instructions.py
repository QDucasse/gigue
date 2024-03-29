import pytest
from unicorn import UcError
from unicorn.riscv_const import UC_RISCV_REG_T1

from gigue.constants import INSTRUCTIONS_INFO
from gigue.helpers import reverse_endianness, to_signed, to_unsigned
from gigue.instructions import (
    BInstruction,
    IInstruction,
    Instruction,
    JInstruction,
    RInstruction,
    SInstruction,
    UInstruction,
)
from tests.conftest import (
    ADDRESS,
    DATA_ADDRESS,
    TEST_DATA_REG,
    UC_DATA_REG,
    cap_disasm_bytes,
)

# =================================
#            Helpers
# =================================


def imm_str(immediate):
    if -0xA < immediate < 0xA:
        return str(immediate)
    else:
        return hex(immediate)


# =================================
#         Sign Extension
# =================================


@pytest.mark.parametrize(
    "value,size,expected",
    [
        (-16, 12, 0xFF0),
        (16, 12, 0x010),
        (1, 12, 0x001),
        (2048, 13, 0x800),
    ],
)
def test_signed_to_unsigned(value, size, expected):
    assert expected == to_unsigned(value, size)


@pytest.mark.parametrize(
    "value,size,expected",
    [
        (0xFF0, 12, -16),
        (0x010, 12, 16),
        (0x001, 12, 1),
        (0x800, 13, 2048),
    ],
)
def test_unsigned_to_signed(value, size, expected):
    assert expected == to_signed(value, size)


# =================================
#           Instruction
# =================================


def test_instruction_superclass():
    with pytest.raises(NotImplementedError):
        instr = Instruction("test", 0b0101010)
        instr.generate()


# =================================
#         R Instructions
# =================================


@pytest.mark.parametrize(
    "name",
    [
        "add",
        "addw",
        "andr",
        "mul",
        "mulh",
        "mulhsu",
        "mulhu",
        "mulw",
        "orr",
        "sll",
        "sllw",
        "slt",
        "sltu",
        "sra",
        "sraw",
        "srl",
        "srlw",
        "sub",
        "subw",
        "xor",
    ],
)
def test_correct_encoding_rinstr(name, disasm_setup):
    constr = getattr(RInstruction, name)
    instr = constr(rd=5, rs1=6, rs2=7)
    mc_instr = instr.generate()
    assert instr.opcode == INSTRUCTIONS_INFO[name].opcode
    assert instr.funct3 == INSTRUCTIONS_INFO[name].funct3
    # Disassembly
    disasm = disasm_setup
    assert instr.rd == disasm.extract_rd(mc_instr)
    assert instr.rs1 == disasm.extract_rs1(mc_instr)
    assert instr.rs2 == disasm.extract_rs2(mc_instr)
    assert instr.funct7 == disasm.extract_funct7(mc_instr)


@pytest.mark.parametrize(
    "name",
    [
        "add",
        "addw",
        "mul",
        "mulh",
        "mulhsu",
        "mulhu",
        "mulw",
        "sll",
        "sllw",
        "slt",
        "sltu",
        "sra",
        "sraw",
        "srl",
        "srlw",
        "sub",
        "subw",
        "xor",
    ],
)
def test_capstone_rinstr(name, cap_disasm_setup):
    constr = getattr(RInstruction, name)
    instr = constr(rd=5, rs1=6, rs2=7)
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == name
    assert instr_disasm.op_str == "t0, t1, t2"


@pytest.mark.parametrize("name", ["andr", "orr"])
def test_capstone_rinstr_special_cases(name, cap_disasm_setup):
    constr = getattr(RInstruction, name)
    instr = constr(rd=5, rs1=6, rs2=7)
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic + "r" == name
    assert instr_disasm.op_str == "t0, t1, t2"


@pytest.mark.parametrize(
    "name",
    [
        "add",
        "addw",
        "andr",
        "mul",
        "mulh",
        "mulhsu",
        "mulhu",
        "mulw",
        "orr",
        "sll",
        "sllw",
        "slt",
        "sltu",
        "sra",
        "sraw",
        "srl",
        "srlw",
        "sub",
        "subw",
        "xor",
    ],
)
def test_unicorn_smoke_rinstr(name, cap_disasm_setup, uc_emul_setup, handler_setup):
    constr = getattr(RInstruction, name)
    instr = constr(rd=5, rs1=6, rs2=7)
    bytes = instr.generate_bytes()
    # Disassembler
    cap_disasm = cap_disasm_setup
    cap_disasm_bytes(cap_disasm, bytes, ADDRESS)
    # Emulation
    uc_emul = uc_emul_setup
    uc_emul.mem_write(ADDRESS, bytes)
    # Handler
    handler = handler_setup
    handler.hook_instr_tracer(uc_emul)
    uc_emul.emu_start(ADDRESS, ADDRESS + len(bytes))
    uc_emul.emu_stop()


# =================================
#         I Instructions
# =================================


@pytest.mark.parametrize(
    "name",
    [
        "addi",
        "addiw",
        "andi",
        "jalr",
        "lb",
        "lbu",
        "ld",
        "lh",
        "lhu",
        "lw",
        "lwu",
        "ori",
        "slti",
        "sltiu",
        "xori",
    ],
)
@pytest.mark.parametrize(
    "imm", [0x00, 0x01, 0x1C, 0xFF, 0x7FF, -0x01, -0x1C, -0xFF, -0x7FF]
)
def test_correct_encoding_iinstr(name, imm, disasm_setup):
    constr = getattr(IInstruction, name)
    instr = constr(rd=5, rs1=6, imm=imm)
    mc_instr = instr.generate()
    # Disassembly
    disasm = disasm_setup
    assert instr.opcode == INSTRUCTIONS_INFO[name].opcode
    assert instr.funct3 == INSTRUCTIONS_INFO[name].funct3
    assert instr.rd == disasm.extract_rd(mc_instr)
    assert instr.rs1 == disasm.extract_rs1(mc_instr)
    assert instr.imm == disasm.extract_imm_i(mc_instr)


@pytest.mark.parametrize("name", ["slli", "slliw", "srai", "sraiw", "srli", "srliw"])
@pytest.mark.parametrize(
    "imm", [0x00, 0x01, 0x1C, 0xFF, 0x7FF, -0x01, -0x1C, -0xFF, -0x7FF]
)
def test_correct_encoding_iinstr_shifts(name, imm, disasm_setup):
    constr = getattr(IInstruction, name)
    instr = constr(rd=5, rs1=6, imm=imm)
    mc_instr = instr.generate()
    assert instr.opcode == INSTRUCTIONS_INFO[name].opcode
    assert instr.funct3 == INSTRUCTIONS_INFO[name].funct3
    # Disassembly
    disasm = disasm_setup
    assert instr.rd == disasm.extract_rd(mc_instr)
    assert instr.rs1 == disasm.extract_rs1(mc_instr)
    imm_disasm = disasm.extract_imm_i(mc_instr)
    if name.endswith("w"):
        masked_imm = imm_disasm & 0x1F
    else:
        masked_imm = imm_disasm & 0x2F
    assert instr.imm == masked_imm


# TODO: Special cases 0x00, 0x01, -0x01
@pytest.mark.parametrize(
    "name", ["addi", "addiw", "andi", "jalr", "ori", "slti", "sltiu", "xori"]
)
@pytest.mark.parametrize("imm", [0x1C, 0xFF, 0x7FF, -0x1C, -0xFF, -0x7FF])
def test_capstone_iinstr(name, imm, cap_disasm_setup):
    constr = getattr(IInstruction, name)
    instr = constr(rd=5, rs1=6, imm=imm)
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == name
    assert instr_disasm.op_str == "t0, t1, " + imm_str(imm)


@pytest.mark.parametrize("name", ["slli", "slliw", "srai", "sraiw", "srli", "srliw"])
@pytest.mark.parametrize("imm", [0x0, 0x1, 0xF, 0x1F, 0x3F, -0x1, -0xF, -0x1F, -0x3F])
def test_capstone_iinstr_shifts(name, imm, cap_disasm_setup):
    constr = getattr(IInstruction, name)
    instr = constr(rd=5, rs1=6, imm=imm)
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == name
    imm = (imm & 0x1F) if name.endswith("w") else (imm & 0x2F)
    assert instr_disasm.op_str == "t0, t1, " + imm_str(imm)


@pytest.mark.parametrize("name", ["lb", "lbu", "ld", "lh", "lhu", "lw", "lwu"])
@pytest.mark.parametrize("imm", [0x0, 0x1, 0xF, 0x1F, 0x7FF, -0x1, -0xF, -0x1F, -0x7FF])
def test_capstone_iinstr_loads(name, imm, cap_disasm_setup):
    constr = getattr(IInstruction, name)
    instr = constr(rd=5, rs1=6, imm=imm)
    bytes = instr.generate_bytes()
    cap_disasm = cap_disasm_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == name
    assert instr_disasm.op_str == "t0, " + imm_str(imm) + "(t1)"


def test_capstone_ebreak(cap_disasm_setup, uc_emul_setup):
    instr = IInstruction.ebreak()
    bytes = instr.generate_bytes()
    cap_disasm = cap_disasm_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == "ebreak"
    with pytest.raises(UcError):
        uc_emul = uc_emul_setup
        uc_emul.mem_write(ADDRESS, bytes)
        uc_emul.emu_start(ADDRESS, ADDRESS + 4)


@pytest.mark.parametrize(
    "name, expected",
    [
        ("lb", 0x10),
        ("lbu", 0x10),
        ("ld", 0xFEDCBA9876543210),
        ("lh", 0x3210),
        ("lhu", 0x3210),
        ("lw", 0x76543210),
        ("lwu", 0x76543210),
    ],
)  # Note: Tests are performed using reversed endianness (easier to follow for me!)
def test_unicorn_iinstr_loads(name, expected, cap_disasm_setup, uc_emul_setup):
    constr = getattr(IInstruction, name)
    instr = constr(rs1=TEST_DATA_REG, rd=6, imm=0)
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Emulation
    uc_emul = uc_emul_setup
    uc_emul.reg_write(UC_DATA_REG, DATA_ADDRESS)
    uc_emul.reg_write(UC_RISCV_REG_T1, 0x0)
    uc_emul.mem_write(
        DATA_ADDRESS, reverse_endianness(b"\xfe\xdc\xba\x98\x76\x54\x32\x10")
    )
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, ADDRESS + 4)
    uc_emul.emu_stop()
    assert uc_emul.reg_read(UC_RISCV_REG_T1) == expected


@pytest.mark.parametrize(
    "name, expected",
    [
        ("lb", 0xFFFFFFFFFFFFFFFF),
        ("lbu", 0xFF),
        ("ld", 0xFFFFFFFFFFFFFFFF),
        ("lh", 0xFFFFFFFFFFFFFFFF),
        ("lhu", 0xFFFF),
        ("lw", 0xFFFFFFFFFFFFFFFF),
        ("lwu", 0xFFFFFFFF),
    ],
)
def test_unicorn_iinstr_loads_sign_extension(
    name, expected, cap_disasm_setup, uc_emul_setup
):
    constr = getattr(IInstruction, name)
    instr = constr(rs1=TEST_DATA_REG, rd=6, imm=0)
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Emulation
    uc_emul = uc_emul_setup
    uc_emul.reg_write(UC_DATA_REG, DATA_ADDRESS)
    uc_emul.reg_write(UC_RISCV_REG_T1, 0x0)
    uc_emul.mem_write(
        DATA_ADDRESS, reverse_endianness(b"\xff\xff\xff\xff\xff\xff\xff\xff")
    )
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, ADDRESS + 4)
    uc_emul.emu_stop()
    assert uc_emul.reg_read(UC_RISCV_REG_T1) == expected


@pytest.mark.parametrize("name", ["lb", "lbu", "ld", "lh", "lhu", "lw", "lwu"])
@pytest.mark.parametrize("imm", [0x0, 0x1, 0xF, 0x1F, 0x7FF, -0x1, -0xF, -0x1F, -0x7FF])
def test_unicorn_iinstr_loads_smoke(
    name, imm, cap_disasm_setup, uc_emul_setup, handler_setup
):
    constr = getattr(IInstruction, name)
    instr = constr(rs1=TEST_DATA_REG, rd=6, imm=imm)
    bytes = instr.generate_bytes()
    # Disassembler
    cap_disasm = cap_disasm_setup
    cap_disasm_bytes(cap_disasm, bytes, ADDRESS)
    # Emulation
    uc_emul = uc_emul_setup
    uc_emul.mem_write(ADDRESS, bytes)
    # Handler
    handler = handler_setup
    handler.hook_instr_tracer(uc_emul)
    uc_emul.reg_write(UC_DATA_REG, DATA_ADDRESS + 0x7FF)  # To test negatives values!
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, ADDRESS + 4)
    uc_emul.emu_stop()


# =================================
#         U Instructions
# =================================


@pytest.mark.parametrize("name", ["auipc", "lui"])
@pytest.mark.parametrize(
    "imm", [0x00001FFF, 0x7FFFF000, 0x7FFFFFFF, -0x00001FFF, -0x7FFFF000, -0x7FFFFFFF]
)
def test_correct_encoding_uinstr(name, imm, disasm_setup):
    constr = getattr(UInstruction, name)
    instr = constr(rd=5, imm=imm)
    mc_instr = instr.generate()
    assert instr.opcode == INSTRUCTIONS_INFO[name].opcode
    # Disassembly
    disasm = disasm_setup
    assert instr.rd == disasm.extract_rd(mc_instr)
    assert instr.imm & 0xFFFFF000 == disasm.extract_imm_u(mc_instr)


@pytest.mark.parametrize("name", ["auipc", "lui"])
@pytest.mark.parametrize(
    "imm", [0x00001FFF, 0x7FFFF000, 0x7FFFFFFF, -0x00001FFF, -0x7FFFF000, -0x7FFFFFFF]
)
def test_capstone_uinstr(name, imm, cap_disasm_setup):
    constr = getattr(UInstruction, name)
    instr = constr(rd=5, imm=imm)
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == name
    assert instr_disasm.op_str == "t0, " + imm_str((imm & 0xFFFFF000) >> 12)


# =================================
#         J Instructions
# =================================


@pytest.mark.parametrize(
    "imm,res",
    [
        (0x7FFFFFFF, 0xFFFFF),
        (0x7FFFF000, 0x800FF),
        (0x00001FFF, 0x7FF01),
        (0x000001FF, 0x1FE00),
        (0x001FFFFE, 0xFFFFF),
    ],
)
def test_immediate_shuffle(imm, res):
    instr = JInstruction("rand", 0b1111111, 6, imm)
    shuffle = instr.shuffle_imm()
    assert shuffle == res


@pytest.mark.parametrize("name", ["jal"])
@pytest.mark.parametrize(
    "imm",
    [
        0x0,
        0x1,
        0x1FF,
        0x1FFF,
        0x01FFFF,
        0xFFFFF,
        -0x1,
        -0x1FF,
        -0x1FFF,
        -0x01FFFF,
        -0xFFFFF,
    ],
)
def test_correct_encoding_jinstr(name, imm, disasm_setup):
    constr = getattr(JInstruction, name)
    instr = constr(rd=5, imm=imm)
    mc_instr = instr.generate()
    assert instr.opcode == INSTRUCTIONS_INFO[name].opcode
    # Disassembly
    disasm = disasm_setup
    assert instr.rd == disasm.extract_rd(mc_instr)
    assert instr.imm == disasm.extract_imm_j(mc_instr)


@pytest.mark.parametrize("name", ["jal"])
@pytest.mark.parametrize(
    "imm",
    [
        0x0,
        0x1,
        0x1FF,
        0x1FFF,
        0x01FFFF,
        0xFFFFF,
        -0x1,
        -0x1FF,
        -0x1FFF,
        -0x01FFFF,
        -0xFFFFF,
    ],
)
def test_capstone_jinstr(name, imm, cap_disasm_setup):
    constr = getattr(JInstruction, name)
    instr = constr(rd=5, imm=imm)
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == name
    # Ugly way to align the value: pass to unsigned,
    # remove last bit then re-sign the value!
    assert instr_disasm.op_str == "t0, " + imm_str(
        to_signed(to_unsigned(imm, 21) & 0x1FFFFE, 21)
    )


# =================================
#         S Instructions
# =================================


@pytest.mark.parametrize("name", ["sb", "sd", "sh", "sw"])
@pytest.mark.parametrize("imm", [0x0, 0x1, 0x1F, 0x7FF, -0x0, -0x1, -0x1F, -0x7FF])
def test_correct_encoding_sinstr(name, imm, disasm_setup):
    constr = getattr(SInstruction, name)
    instr = constr(rs1=5, rs2=6, imm=imm)
    mc_instr = instr.generate()
    assert instr.opcode == INSTRUCTIONS_INFO[name].opcode
    assert instr.funct3 == INSTRUCTIONS_INFO[name].funct3
    # Disassembly
    disasm = disasm_setup
    assert instr.rs1 == disasm.extract_rs1(mc_instr)
    assert instr.rs2 == disasm.extract_rs2(mc_instr)
    assert instr.imm == disasm.extract_imm_s(mc_instr)


@pytest.mark.parametrize("name", ["sb", "sd", "sh", "sw"])
@pytest.mark.parametrize("imm", [0x0, 0x1, 0x1F, 0x7FF, -0x0, -0x1, -0x1F, -0x7FF])
def test_capstone_sinstr(name, imm, cap_disasm_setup):
    constr = getattr(SInstruction, name)
    instr = constr(rs1=5, rs2=6, imm=imm)
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == name
    assert instr_disasm.op_str == "t1, " + imm_str(imm) + "(t0)"


@pytest.mark.parametrize(
    "name, expected",
    [
        ("sb", b"\x00\x00\x00\x00\x00\x00\x00\x10"),
        ("sh", b"\x00\x00\x00\x00\x00\x00\x32\x10"),
        ("sw", b"\x00\x00\x00\x00\x76\x54\x32\x10"),
        ("sd", b"\xfe\xdc\xba\x98\x76\x54\x32\x10"),
    ],
)  # Note: Tests are performed using reversed endianness (easier to follow for me!)
def test_unicorn_sinstr(name, expected, cap_disasm_setup, uc_emul_setup, handler_setup):
    constr = getattr(SInstruction, name)
    instr = constr(rs1=TEST_DATA_REG, rs2=6, imm=0)
    bytes = instr.generate_bytes()
    # Disassembler
    cap_disasm = cap_disasm_setup
    cap_disasm_bytes(cap_disasm, bytes, ADDRESS)
    # Emulation
    uc_emul = uc_emul_setup
    uc_emul.mem_write(ADDRESS, bytes)
    # Handler
    handler = handler_setup
    handler.hook_instr_tracer(uc_emul)
    # Emulation
    uc_emul = uc_emul_setup
    uc_emul.reg_write(UC_DATA_REG, DATA_ADDRESS)
    uc_emul.reg_write(UC_RISCV_REG_T1, 0xFEDCBA9876543210)
    uc_emul.mem_write(DATA_ADDRESS, b"\x00\x00\x00\x00\x00\x00\x00\x00")
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, ADDRESS + 4)
    uc_emul.emu_stop()
    assert reverse_endianness(uc_emul.mem_read(DATA_ADDRESS, 8)) == expected


@pytest.mark.parametrize("name", ["sb", "sd", "sh", "sw"])
@pytest.mark.parametrize("imm", [0x0, 0x1, 0x1F, 0x7FF, -0x0, -0x1, -0x1F, -0x7FF])
def test_unicorn_sinstr_smoke(name, imm, cap_disasm_setup, uc_emul_setup):
    constr = getattr(SInstruction, name)
    instr = constr(rs1=TEST_DATA_REG, rs2=6, imm=imm)
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Emulation
    uc_emul = uc_emul_setup
    uc_emul.reg_write(UC_DATA_REG, DATA_ADDRESS + 0x7FF)  # To test negative offsets!
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, ADDRESS + 4)
    uc_emul.emu_stop()


# =================================
#         B Instructions
# =================================


# Note: Accesses aligned (bit 0 ignored)
@pytest.mark.parametrize("name", ["beq", "bge", "bgeu", "blt", "bltu", "bne"])
@pytest.mark.parametrize("imm", [0x0, 0x1, 0x1F, 0x7FF, -0x1, -0x1F, -0x7FF])
def test_correct_encoding_binstr(name, imm, disasm_setup):
    constr = getattr(BInstruction, name)
    instr = constr(rs1=5, rs2=6, imm=imm)
    mc_instr = instr.generate()
    assert instr.opcode == INSTRUCTIONS_INFO[name].opcode
    assert instr.funct3 == INSTRUCTIONS_INFO[name].funct3
    # Disassembly
    disasm = disasm_setup
    assert instr.rs1 == disasm.extract_rs1(mc_instr)
    assert instr.rs2 == disasm.extract_rs2(mc_instr)
    assert instr.imm == disasm.extract_imm_b(mc_instr)


# Note: Accesses aligned (bit 0 ignored)
@pytest.mark.parametrize("name", ["beq", "bge", "bgeu", "blt", "bltu", "bne"])
@pytest.mark.parametrize("imm", [0x0, 0x1, 0x1F, 0x7FF, -0x1, -0x1F, -0x7FF])
def test_capstone_binstr(name, imm, cap_disasm_setup):
    constr = getattr(BInstruction, name)
    instr = constr(rs1=5, rs2=6, imm=imm)
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == name
    assert instr_disasm.op_str == "t0, t1, " + imm_str(
        to_signed(to_unsigned(imm, 13) & 0x1FFE, 13)
    )
