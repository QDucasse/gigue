import pytest

from gigue.constants import INSTRUCTIONS_INFO
from gigue.disassembler import Disassembler
from gigue.rot.rot_constants import ROT_INSTRUCTIONS_INFO
from tests.conftest import Handler


class RotHandler(Handler):
    def handle_rol(self, uc_emul, pc, instr):
        # rol rd, rs1, rs2:
        # shamt = x(rs2)[5:0]
        # x(rd) = x(rs1) << shamt | x(rs1) >> (xlen - shamt)
        rs1 = self.disasm.extract_rs1(instr)
        rs2 = self.disasm.extract_rs2(instr)
        rd = self.disasm.extract_rd(instr)
        val = uc_emul.reg_read(rs1 + 1)
        shamt = uc_emul.reg_read(rs2 + 1)
        uc_emul.reg_write(rd + 1, val << shamt)

    def handle_ror(self, uc_emul, pc, instr):
        # ror rd, rs1, rs2:
        # shamt = x(rs2)[5:0]
        # x(rd) = x(rs1) >> shamt | x(rs1) << (xlen - shamt)
        rs1 = self.disasm.extract_rs1(instr)
        rs2 = self.disasm.extract_rs2(instr)
        rd = self.disasm.extract_rd(instr)
        val = uc_emul.reg_read(rs1 + 1)
        shamt = uc_emul.reg_read(rs2 + 1)
        uc_emul.reg_write(rd + 1, val >> shamt)

    def handle_rori(self, uc_emul, pc, instr):
        # ror rd, rs1, shamt:
        # x(rd) = x(rs1) >> shamt | x(rs1) << (xlen - shamt)
        rs1 = self.disasm.extract_rs1(instr)
        shamt = self.disasm.extract_imm(instr)
        rd = self.disasm.extract_rd(instr)
        val = uc_emul.reg_read(rs1 + 1)
        uc_emul.reg_write(rd + 1, val >> shamt)


@pytest.fixture
def fixer_disasm_setup():
    # FIXME: Merging dicts with the ROT info first
    disassembler = Disassembler(ROT_INSTRUCTIONS_INFO | INSTRUCTIONS_INFO)
    return disassembler


@pytest.fixture
def rot_handler_setup(fixer_disasm_setup):
    return RotHandler(fixer_disasm_setup)
