from gigue.constants import INSTRUCTIONS_INFO
from gigue.rimi.rimi_constants import RIMI_INSTRUCTIONS_INFO
from gigue.rimi.rimi_instructions import RIMIIInstruction, RIMISInstruction

if __name__ == "__main__":
    # TODO: Add logic for:
    #    - Rocket display
    #    - Single instruction bin generation
    import os
    import shutil
    import subprocess
    import sys
    from typing import Dict, List

    from gigue.constants import BIN_DIR
    from gigue.instructions import IInstruction, Instruction, UInstruction

    instrs: Dict[str, Instruction] = {
        "lb1": RIMIIInstruction.lb1(rd=10, rs1=31, imm=123),
        "lh1": RIMIIInstruction.lh1(rd=10, rs1=31, imm=123),
        "lw1": RIMIIInstruction.lw1(rd=10, rs1=31, imm=123),
        "ld1": RIMIIInstruction.ld1(rd=10, rs1=31, imm=123),
        "lbu1": RIMIIInstruction.lbu1(rd=10, rs1=31, imm=123),
        "lhu1": RIMIIInstruction.lhu1(rd=10, rs1=31, imm=123),
        "lwu1": RIMIIInstruction.lwu1(rd=10, rs1=31, imm=0),
        "sb1": RIMISInstruction.sb1(rs1=31, rs2=10, imm=123),
        "sh1": RIMISInstruction.sh1(rs1=31, rs2=10, imm=123),
        "sw1": RIMISInstruction.sw1(rs1=31, rs2=10, imm=123),
        "sd1": RIMISInstruction.sd1(rs1=31, rs2=10, imm=123),
        "ls": RIMIIInstruction.ls(rd=1, rs1=28, imm=0),
        "ss": RIMISInstruction.ss(rs1=28, rs2=1, imm=0),
        "chdom": RIMIIInstruction.chdom(0, 6, 0),
        "retdom": RIMIIInstruction.retdom(),
    }

    # Instructions examples
    instr_examples: Dict[str, List[Instruction]] = {
        "lb1": [RIMIIInstruction.lb1(rd=10, rs1=31, imm=123)],
        "lh1": [RIMIIInstruction.lh1(rd=10, rs1=31, imm=123)],
        "lw1": [RIMIIInstruction.lw1(rd=10, rs1=31, imm=123)],
        "ld1": [RIMIIInstruction.ld1(rd=10, rs1=31, imm=123)],
        "lbu1": [RIMIIInstruction.lbu1(rd=10, rs1=31, imm=123)],
        "lhu1": [RIMIIInstruction.lhu1(rd=10, rs1=31, imm=123)],
        "lwu1": [RIMIIInstruction.lwu1(rd=10, rs1=31, imm=0)],
        "sb1": [RIMISInstruction.sb1(rs1=31, rs2=10, imm=123)],
        "sh1": [RIMISInstruction.sh1(rs1=31, rs2=10, imm=123)],
        "sw1": [RIMISInstruction.sw1(rs1=31, rs2=10, imm=123)],
        "sd1": [RIMISInstruction.sd1(rs1=31, rs2=10, imm=123)],
        "ls": [RIMIIInstruction.ls(rd=1, rs1=28, imm=0)],
        "ss": [RIMISInstruction.ss(rs1=28, rs2=1, imm=0)],
        "chdom": [
            UInstruction.auipc(6, 0),
            IInstruction.addi(6, 6, 12),
            RIMIIInstruction.chdom(0, 6, 0),
            RIMIIInstruction.retdom(),
        ],
    }

    def all_rocket():
        for instr in instrs.values():
            print(
                f"def {instr.name.upper(): <19}="
                ' BitPat("'
                f'{instr.rocket_display(RIMI_INSTRUCTIONS_INFO | INSTRUCTIONS_INFO)}")'
            )

    def solo_instr_bin(name):
        with open("bin/out.bin", "wb") as file:
            list_instr = [instr.generate_bytes() for instr in instr_examples[name]]
            bytes_instr = b"".join(list_instr) + IInstruction.ret().generate_bytes()
            file.write(bytes_instr)

        subprocess.run(["make", "dump"], timeout=10, check=True)

        base_dir = f"{BIN_DIR}/unit"
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
        shutil.copy(
            src=f"{BIN_DIR}/out.elf",
            dst=f"{BIN_DIR}/unit/{instr_name}.elf",
        )
        shutil.copy(
            src=f"{BIN_DIR}/out.dump",
            dst=f"{BIN_DIR}/unit/{instr_name}.dump",
        )

    def riscv_opcodes():
        rv_opcodes = ""
        rv_match_mask = ""
        rv_declares = ""
        for instr in instrs.values():
            rv_opcodes += instr.riscv_opcodes_encode() + "\n"
            rv_match_mask += (
                instr.riscv_opcodes_match_mask(RIMI_INSTRUCTIONS_INFO) + "\n"
            )
            rv_declares += instr.riscv_opcodes_declare_insn() + "\n"
        print(rv_opcodes)
        print(rv_match_mask)
        print(rv_declares)

    argv = sys.argv[1:]
    if argv[0] == "--rocket":
        # Rocket generation
        all_rocket()

    elif argv[0] == "--instr":
        instr_name = argv[1]
        solo_instr_bin(instr_name)

    elif argv[0] == "--all":
        for instr_name in instr_examples.keys():
            solo_instr_bin(instr_name)

    elif argv[0] == "--opcodes":
        riscv_opcodes()
