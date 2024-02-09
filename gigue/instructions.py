from __future__ import annotations

import logging
from typing import Dict, List

from gigue.constants import INSTRUCTIONS_INFO, RoCCCustomInstructionInfo
from gigue.helpers import format_to, format_to_aligned, int_to_bytes32, to_unsigned

# Note: Annotate with current typesss


logger = logging.getLogger("gigue")


class Instruction:
    def __init__(self, name: str, opcode: int, funct7: int = 0):
        self.name: str = name
        self.opcode: int = format_to(opcode, 7)
        self.funct7: int = format_to(funct7, 7)
        self.machine_instruction: int = 0

    def generate_bytes(self) -> bytes:
        return int_to_bytes32(self.generate())

    def riscv_opcodes_encode(self):
        return f"Undefined for this instruction type ({self.__class__.__name__})"

    def riscv_opcodes_match_mask(self, instr_dict=INSTRUCTIONS_INFO):
        cmp_mask = instr_dict[self.name].cmp_mask
        mask = f"#define MASK_{self.name.upper()}  {hex(cmp_mask)}"
        match = f"#define MATCH_{self.name.upper()} {hex(self.generate() & cmp_mask)}"
        return f"{mask}\n{match}"

    def riscv_opcodes_declare_insn(self):
        upper_name = self.name.upper()
        return f"DECLARE_INSN({self.name}, MATCH_{upper_name}, MASK_{upper_name})"

    def generate(self) -> int:
        raise NotImplementedError("Please Implement this method")


class RInstruction(Instruction):
    def __init__(
        self,
        name: str,
        opcode: int,
        funct3: int,
        rd: int,
        rs1: int,
        rs2: int,
        funct7: int = 0,
    ):
        super().__init__(name, opcode, funct7)
        self.funct3: int = format_to(funct3, 3)
        self.rd: int = format_to(rd, 5)
        self.rs1: int = format_to(rs1, 5)
        self.rs2: int = format_to(rs2, 5)

    def __str__(self) -> str:
        return f"<{self.name}, {self.rd} {self.rs1} {self.rs2}>"

    def generate(self) -> int:
        self.machine_instruction = self.opcode
        self.machine_instruction |= self.rd << 7
        self.machine_instruction |= self.funct3 << 12
        self.machine_instruction |= self.rs1 << 15
        self.machine_instruction |= self.rs2 << 20
        self.machine_instruction |= self.funct7 << 25
        return self.machine_instruction

    @classmethod
    def r_instr(cls, name: str, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls(
            name=name,
            opcode=INSTRUCTIONS_INFO[name].opcode,
            funct3=INSTRUCTIONS_INFO[name].funct3,
            rd=rd,
            rs1=rs1,
            rs2=rs2,
            funct7=INSTRUCTIONS_INFO[name].funct7,
        )

    @classmethod
    def add(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("add", rd, rs1, rs2)

    @classmethod
    def addw(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("addw", rd, rs1, rs2)

    @classmethod
    def andr(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("andr", rd, rs1, rs2)

    @classmethod
    def mul(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("mul", rd, rs1, rs2)

    @classmethod
    def mulh(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("mulh", rd, rs1, rs2)

    @classmethod
    def mulhsu(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("mulhsu", rd, rs1, rs2)

    @classmethod
    def mulhu(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("mulhu", rd, rs1, rs2)

    @classmethod
    def mulw(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("mulw", rd, rs1, rs2)

    @classmethod
    def orr(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("orr", rd, rs1, rs2)

    @classmethod
    def sll(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("sll", rd, rs1, rs2)

    @classmethod
    def sllw(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("sllw", rd, rs1, rs2)

    @classmethod
    def slt(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("slt", rd, rs1, rs2)

    @classmethod
    def sltu(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("sltu", rd, rs1, rs2)

    @classmethod
    def sra(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("sra", rd, rs1, rs2)

    @classmethod
    def sraw(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("sraw", rd, rs1, rs2)

    @classmethod
    def srl(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("srl", rd, rs1, rs2)

    @classmethod
    def srlw(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("srlw", rd, rs1, rs2)

    @classmethod
    def sub(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("sub", rd, rs1, rs2)

    @classmethod
    def subw(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("subw", rd, rs1, rs2)

    @classmethod
    def xor(cls, rd: int, rs1: int, rs2: int) -> RInstruction:
        return cls.r_instr("xor", rd, rs1, rs2)


class RoCCCustomInstruction(RInstruction):
    # The instructions info are not known this time and should be provided
    CUSTOM_INSTRUCTIONS_INFO: Dict[str, RoCCCustomInstructionInfo] = {}

    def __init__(self, name: str, xd: int, xs1: int, xs2: int, *args, **kwargs):
        self.xd = format_to(xd, 1)
        self.xs1 = format_to(xs1, 1)
        self.xs2 = format_to(xs2, 1)
        funct3: int = format_to((self.xd << 2) + (self.xs1 << 1) + self.xs2, 3)
        super().__init__(name=name, funct3=funct3, *args, **kwargs)  # type: ignore
        # Note: Type ignore due to star

    @classmethod
    def custom_instr(cls, name, rd, rs1, rs2) -> RoCCCustomInstruction:
        try:
            custom_instr_info: RoCCCustomInstructionInfo = cls.CUSTOM_INSTRUCTIONS_INFO[
                name
            ]
        except KeyError as err:
            logger.exception(err)
            logger.exception(
                "The dictionary with custom info is empty, are you sure it is provided"
                " in the subclass?"
            )
            raise
        return cls(
            xd=custom_instr_info.xd,
            xs1=custom_instr_info.xs1,
            xs2=custom_instr_info.xs2,
            name=name,
            opcode=custom_instr_info.opcode,
            rd=rd,
            rs1=rs1,
            rs2=rs2,
            funct7=custom_instr_info.funct7,
        )


class IInstruction(Instruction):
    def __init__(
        self,
        name: str,
        opcode: int,
        funct3: int,
        rd: int,
        rs1: int,
        imm: int,
        funct7: int = 0,
    ):
        super().__init__(name, opcode, funct7)
        self.funct3: int = format_to(funct3, 3)
        self.rd: int = format_to(rd, 5)
        self.rs1: int = format_to(rs1, 5)
        self.imm: int = format_to(to_unsigned(imm, 12), 12)

    def generate(self) -> int:
        self.machine_instruction = self.opcode
        self.machine_instruction |= self.rd << 7
        self.machine_instruction |= self.funct3 << 12
        self.machine_instruction |= self.rs1 << 15
        self.machine_instruction |= self.imm << 20
        self.machine_instruction |= self.funct7 << 25
        return self.machine_instruction

    @classmethod
    def i_instr(cls, name: str, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls(
            name=name,
            opcode=INSTRUCTIONS_INFO[name].opcode,
            funct3=INSTRUCTIONS_INFO[name].funct3,
            rd=rd,
            rs1=rs1,
            imm=imm,
            funct7=INSTRUCTIONS_INFO[name].funct7,
        )

    @classmethod
    def addi(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls.i_instr("addi", rd, rs1, imm)

    @classmethod
    def addiw(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls.i_instr("addiw", rd, rs1, imm)

    @classmethod
    def andi(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls.i_instr("andi", rd, rs1, imm)

    @classmethod
    def jalr(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls.i_instr("jalr", rd, rs1, imm)

    @classmethod
    def jr(cls, rs1: int) -> IInstruction:
        # jr expands to jalr x0, 0(rs1)
        return cls.i_instr("jalr", 0, rs1, 0)

    @classmethod
    def ret(cls) -> IInstruction:
        # ret expands to jalr x0, 0(x1)
        return cls.i_instr("jalr", 0, 1, 0)

    @classmethod
    def lb(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls.i_instr("lb", rd, rs1, imm)

    @classmethod
    def lbu(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls.i_instr("lbu", rd, rs1, imm)

    @classmethod
    def ld(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls.i_instr("ld", rd, rs1, imm)

    @classmethod
    def lh(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls.i_instr("lh", rd, rs1, imm)

    @classmethod
    def lhu(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls.i_instr("lhu", rd, rs1, imm)

    @classmethod
    def lw(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls.i_instr("lw", rd, rs1, imm)

    @classmethod
    def lwu(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls.i_instr("lwu", rd, rs1, imm)

    @classmethod
    def nop(cls) -> IInstruction:
        return cls.i_instr("addi", 0, 0, 0)

    @classmethod
    def ori(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls.i_instr("ori", rd, rs1, imm)

    @classmethod
    def slli(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        # shamt 6 bits long
        return cls.i_instr("slli", rd, rs1, imm & 0x2F)

    @classmethod
    def slliw(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        # shamt 6 bits long and only valid if shamt[5] = 0
        return cls.i_instr("slliw", rd, rs1, imm & 0x1F)

    @classmethod
    def slti(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls.i_instr("slti", rd, rs1, imm)

    @classmethod
    def sltiu(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls.i_instr("sltiu", rd, rs1, imm)

    @classmethod
    def srai(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        # shamt 6 bits long
        return cls.i_instr("srai", rd, rs1, imm & 0x2F)

    @classmethod
    def sraiw(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        # shamt 6 bits long and only valid if shamt[5] = 0
        return cls.i_instr("sraiw", rd, rs1, imm & 0x1F)

    @classmethod
    def srli(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        # shamt 6 bits long
        return cls.i_instr("srli", rd, rs1, imm & 0x2F)

    @classmethod
    def srliw(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        # shamt 6 bits long and only valid if shamt[5] = 0
        return cls.i_instr("srliw", rd, rs1, imm & 0x1F)

    @classmethod
    def xori(cls, rd: int, rs1: int, imm: int) -> IInstruction:
        return cls.i_instr("xori", rd, rs1, imm)

    @classmethod
    def ebreak(cls) -> IInstruction:
        return cls.i_instr("ebreak", 0, 0, 1)

    @classmethod
    def ecall(cls) -> IInstruction:
        return cls.i_instr("ecall", 0, 0, 0)


class UInstruction(Instruction):
    def __init__(self, name: str, opcode: int, rd: int, imm: int):
        super().__init__(name, opcode)
        self.rd: int = format_to(rd, 5)
        self.imm: int = format_to(to_unsigned(imm, 32), 32)

    def generate(self) -> int:
        self.machine_instruction = self.opcode
        self.machine_instruction |= self.rd << 7
        self.machine_instruction |= self.imm & 0xFFFFF000  # Keep 20 upper bits
        return self.machine_instruction

    @classmethod
    def u_instr(cls, name: str, rd: int, imm: int) -> UInstruction:
        return cls(name=name, opcode=INSTRUCTIONS_INFO[name].opcode, rd=rd, imm=imm)

    @classmethod
    def auipc(cls, rd: int, imm: int) -> UInstruction:
        return cls.u_instr("auipc", rd, imm)

    @classmethod
    def lui(cls, rd: int, imm: int) -> UInstruction:
        return cls.u_instr("lui", rd, imm)


class JInstruction(Instruction):
    def __init__(self, name: str, opcode: int, rd: int, imm: int):
        super().__init__(name, opcode)
        self.rd: int = format_to(rd, 5)
        self.imm: int = format_to_aligned(to_unsigned(imm, 21), 21)

    def shuffle_imm(self) -> int:
        # imm[20 | 10:1 | 11 | 19:12]
        shuffle: int = ((self.imm >> 20) & 0x1) << 19  # 20th bit
        shuffle |= ((self.imm >> 1) & 0x3FF) << 9  # 10th to 1st
        shuffle |= ((self.imm >> 11) & 0x1) << 8  # 11th bit
        shuffle |= (self.imm >> 12) & 0xFF  # 12th to 19th
        return shuffle

    def generate(self) -> int:
        self.machine_instruction = self.opcode
        self.machine_instruction |= self.rd << 7
        self.machine_instruction |= self.shuffle_imm() << 12
        return self.machine_instruction

    @classmethod
    def j_instr(cls, name: str, rd: int, imm: int) -> JInstruction:
        return cls(name, INSTRUCTIONS_INFO[name].opcode, rd, imm)

    @classmethod
    def jal(cls, rd: int, imm: int) -> JInstruction:
        return cls.j_instr("jal", rd, imm)

    @classmethod
    def j(cls, imm: int) -> JInstruction:
        return cls.j_instr("jal", 0, imm)


class SInstruction(Instruction):
    def __init__(
        self, name: str, opcode: int, funct3: int, rs1: int, rs2: int, imm: int
    ):
        super().__init__(name, opcode)
        self.funct3: int = format_to(funct3, 3)
        self.rs1: int = format_to(rs1, 5)
        self.rs2: int = format_to(rs2, 5)
        self.imm: int = format_to(to_unsigned(imm, 12), 12)

    def shuffle_imm(self) -> List[int]:
        # imm1: imm[4:0]
        shuffle1: int = (self.imm & 0x1F) << 7
        # imm2: imm[11:5]
        shuffle2: int = ((self.imm & 0xFE0) >> 5) << 25
        return [shuffle1, shuffle2]

    def generate(self) -> int:
        shuffle1: int
        shuffle2: int
        [shuffle1, shuffle2] = self.shuffle_imm()
        self.machine_instruction = self.opcode
        self.machine_instruction |= shuffle1
        self.machine_instruction |= self.funct3 << 12
        self.machine_instruction |= self.rs1 << 15
        self.machine_instruction |= self.rs2 << 20
        self.machine_instruction |= shuffle2
        return self.machine_instruction

    @classmethod
    def s_instr(cls, name: str, rs1: int, rs2: int, imm: int) -> SInstruction:
        return cls(
            name,
            INSTRUCTIONS_INFO[name].opcode,
            INSTRUCTIONS_INFO[name].funct3,
            rs1,
            rs2,
            imm,
        )

    @classmethod
    def sb(cls, rs1: int, rs2: int, imm: int) -> SInstruction:
        return cls.s_instr("sb", rs1, rs2, imm)

    @classmethod
    def sh(cls, rs1: int, rs2: int, imm: int) -> SInstruction:
        return cls.s_instr("sh", rs1, rs2, imm)

    @classmethod
    def sw(cls, rs1: int, rs2: int, imm: int) -> SInstruction:
        return cls.s_instr("sw", rs1, rs2, imm)

    @classmethod
    def sd(cls, rs1: int, rs2: int, imm: int) -> SInstruction:
        return cls.s_instr("sd", rs1, rs2, imm)


class BInstruction(Instruction):
    def __init__(
        self, name: str, opcode: int, funct3: int, rs1: int, rs2: int, imm: int
    ):
        super().__init__(name, opcode)
        self.funct3: int = format_to(funct3, 3)
        self.rs1: int = format_to(rs1, 5)
        self.rs2: int = format_to(rs2, 5)
        self.imm: int = format_to_aligned(to_unsigned(imm, 13), 13)

    def shuffle_imm(self) -> List[int]:
        # imm1: imm[12|10:5]
        shuffle1: int = ((self.imm >> 12) & 0x1) << 6  # 12th bit
        shuffle1 |= (self.imm >> 5) & 0x3F  # 10th to 5th
        # imm2: imm[4:1|11]
        shuffle2: int = ((self.imm >> 1) & 0xF) << 1  # 4th to 1st
        shuffle2 |= (self.imm >> 11) & 0x1  # 11th
        return [shuffle1, shuffle2]

    def generate(self) -> int:
        shuffle1: int
        shuffle2: int
        [shuffle1, shuffle2] = self.shuffle_imm()
        self.machine_instruction = self.opcode
        self.machine_instruction |= shuffle2 << 7
        self.machine_instruction |= self.funct3 << 12
        self.machine_instruction |= self.rs1 << 15
        self.machine_instruction |= self.rs2 << 20
        self.machine_instruction |= shuffle1 << 25
        return self.machine_instruction

    @classmethod
    def b_instr(cls, name: str, rs1: int, rs2: int, imm: int) -> BInstruction:
        return cls(
            name,
            INSTRUCTIONS_INFO[name].opcode,
            INSTRUCTIONS_INFO[name].funct3,
            rs1,
            rs2,
            imm,
        )

    @classmethod
    def beq(cls, rs1: int, rs2: int, imm: int) -> BInstruction:
        return cls.b_instr("beq", rs1, rs2, imm)

    @classmethod
    def bge(cls, rs1: int, rs2: int, imm: int) -> BInstruction:
        return cls.b_instr("bge", rs1, rs2, imm)

    @classmethod
    def bgeu(cls, rs1: int, rs2: int, imm: int) -> BInstruction:
        return cls.b_instr("bgeu", rs1, rs2, imm)

    @classmethod
    def blt(cls, rs1: int, rs2: int, imm: int) -> BInstruction:
        return cls.b_instr("blt", rs1, rs2, imm)

    @classmethod
    def bltu(cls, rs1: int, rs2: int, imm: int) -> BInstruction:
        return cls.b_instr("bltu", rs1, rs2, imm)

    @classmethod
    def bne(cls, rs1: int, rs2: int, imm: int) -> BInstruction:
        return cls.b_instr("bne", rs1, rs2, imm)
