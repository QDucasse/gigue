import logging
from typing import Dict, List, Set

from gigue.constants import OPCODES_NAMES, InstructionInfo

logger = logging.getLogger("prelude")


# FIXME: meh..
ALL_OPCODES_NAMES: Dict[int, str] = OPCODES_NAMES

# Base Helper
# \____________


class Helper:
    def get_output(self, *args, **kwargs):
        raise NotImplementedError("Please implement this method in your helper")


# GNU Helper
# \___________


class GNUHelper(Helper):
    @staticmethod
    def get_rvo_opcode(instr_info: InstructionInfo) -> str:
        opcode_encodings: Dict[str, str] = {
            "I": (
                f"{instr_info.name:<8}rd rs1 imm12"
                f" 14..12={instr_info.funct3} 6..2="
                f"{hex((instr_info.opcode & 0x7C) >> 2)}"
                f" 1..0={instr_info.opcode & 0x3}"
            ),
            "R": (
                f"{instr_info.name:<8}rd rs1 rs2 31..25={instr_info.funct7}"
                f" 14..12={instr_info.funct3} 6..2="
                f"{hex((instr_info.opcode & 0x7C) >> 2)}"
                f" 1..0={instr_info.opcode & 0x3}"
            ),
            "S": (
                f"{instr_info.name:<8}imm12hi rs1 rs2 imm12lo"
                f" 14..12={instr_info.funct3} 6..2="
                f"{hex((instr_info.opcode & 0x7C) >> 2)}"
                f" 1..0={instr_info.opcode & 0x3}"
            ),
        }

        try:
            encoding = opcode_encodings[instr_info.instr_type]
        except KeyError as err:
            raise KeyError(
                f"Instruction {instr_info.name} is of type {instr_info.instr_type}"
                " that does not define an opcode encoding."
            ) from err
        return encoding

    @staticmethod
    def get_gnu_match_mask(instr_info: InstructionInfo) -> str:
        name: str = instr_info.name
        cmp_mask: int = instr_info.cmp_mask
        cmp_val: int = instr_info.cmp_val
        mask = f"#define MASK_{name.upper()}  {hex(cmp_mask)}"
        match = f"#define MATCH_{name.upper()} {hex(cmp_val & cmp_mask)}"
        return f"{mask}\n{match}"

    @staticmethod
    def get_gnu_declare(instr_name: str) -> str:
        upper_name = instr_name.upper()
        return f"DECLARE_INSN({instr_name}, MATCH_{upper_name}, MASK_{upper_name})"

    def get_output(
        self, instr_names: List[str], instrs_info: Dict[str, InstructionInfo]
    ) -> str:
        rvo_opcodes = ""
        gnu_matches_masks = ""
        gnu_declares = ""
        for instr_name in instr_names:
            try:
                instr_info = instrs_info[instr_name]
                rvo_opcodes += self.get_rvo_opcode(instr_info) + "\n"
                gnu_matches_masks += self.get_gnu_match_mask(instr_info) + "\n"
                gnu_declares += self.get_gnu_declare(instr_name) + "\n"
            except KeyError as err:
                logger.error(err)
                raise
        return (
            f"# Include in: riscv-opcodes/opcodes\n{rvo_opcodes}\n"
            "# Include in: riscv-gnu-toolchain/binutils/include/opcode/"
            "riscv-opc.h (or the same files in gdb)\n"
            f"{gnu_matches_masks}\n{gnu_declares}"
        )


# Rocket Helper
# \______________


class RocketHelper(Helper):
    @staticmethod
    def get_bitpats(instr_info: InstructionInfo) -> str:
        cmp_mask: str = format(instr_info.cmp_mask, "#034b")
        cmp_val: str = format(instr_info.cmp_val, "#034b")
        rocket_bin = "b"
        for bit in range(2, len(cmp_mask)):
            if cmp_mask[bit] == "0":
                rocket_bin += "?"
            else:
                rocket_bin += cmp_val[bit]
        return f'def {instr_info.name.upper(): <19}= BitPat("{rocket_bin}")'

    def get_output(
        self, instr_names: List[str], instrs_info: Dict[str, InstructionInfo]
    ) -> str:
        bitpats = ""
        for instr_name in instr_names:
            instr_info: InstructionInfo = instrs_info[instr_name]
            bitpats += self.get_bitpats(instr_info) + "\n"
        return f"# Include in: rocket/scala/rocket/Instruction.scala\n{bitpats}"


# CVA6 Helper
# \____________


class CVA6Helper(Helper):
    @staticmethod
    def get_opcode(instr_info: InstructionInfo) -> str:
        opcode: str = format(instr_info.opcode, "#09b")
        return (
            f"localparam {ALL_OPCODES_NAMES[instr_info.opcode]:<16}="
            f" 7'b{opcode[2:4]}_{opcode[4:7]}_{opcode[7:9]}"
        )

    def get_output(
        self, instr_names: List[str], instrs_info: Dict[str, InstructionInfo]
    ) -> str:
        met_opcodes: Set[str] = set()
        names: str = ""
        opcodes: str = ""
        for instr_name in instr_names:
            instr_info: InstructionInfo = instrs_info[instr_name]
            instr_opcode: str = bin(instr_info.opcode)
            if instr_opcode not in met_opcodes:
                met_opcodes.add(instr_opcode)
                opcodes += f"{self.get_opcode(instr_info)}" + "\n"
            names += f"{instr_name.upper()}, "
        return (
            f"# Include in: cva6/core/ariane_pkg.sv:fu_op\n{names}\n"
            f"# Include in: cva6/core/include/riscv_pkg.sv\n{opcodes}\n"
        )
