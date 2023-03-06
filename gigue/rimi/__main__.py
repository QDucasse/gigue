from gigue.instructions import IInstruction, SInstruction
from gigue.rimi.instructions import RIMIIInstruction, RIMISInstruction

if __name__ == "__main__":
    # Example with base address for domain 0 in t0 (x5), domain 1 in t1 (x6)

    instructions = [
        # Base loads/stores in a correct domain
        IInstruction.lw(rd=30, rs1=5, imm=0),
        SInstruction.sw(rs1=5, rs2=30, imm=0),
        # Duplicated load/store in a correct domain
        RIMIIInstruction.lw1(rd=31, rs1=6, imm=0),
        RIMISInstruction.sw1(rs1=6, rs2=30, imm=0),
        # Base load/store in an incorrect domain
        IInstruction.lw(rd=30, rs1=6, imm=0),
        SInstruction.sw(rs1=6, rs2=30, imm=0),
        # Duplicated load/store in an incorrect domain
        RIMIIInstruction.lw1(rd=31, rs1=5, imm=0),
        RIMISInstruction.sw1(rs1=5, rs2=30, imm=0),
    ]

    bytes = b"".join([instr.generate_bytes() for instr in instructions])

    with open("bin/rimi.bin", "bw") as file:
        file.write(bytes)

    # Disassembly
    # from capstone import CS_ARCH_RISCV
    # from capstone import CS_MODE_RISCV64
    # from capstone import Cs

    # cap_disasm = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
    # for i in cap_disasm.disasm(bytes, 0x1000):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
