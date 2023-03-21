import pytest
from unicorn.riscv_const import UC_RISCV_REG_RA, UC_RISCV_REG_T3, UC_RISCV_REG_T4

from gigue.constants import INSTRUCTIONS_INFO
from gigue.disassembler import Disassembler
from gigue.helpers import bytes_to_int, int_to_bytes32, int_to_bytes64
from gigue.instructions import IInstruction, SInstruction
from gigue.rimi.constants import (
    RIMI_DATA_REG_D1,
    RIMI_INSTRUCTIONS_INFO,
    RIMI_SHADOW_STACK_REG,
)
from tests.conftest import DATA_ADDRESS, Handler

# Check for correct test data reg and shadow stack reg, config vs unicorn one
# Note: Unicorn's 0 is the code for invalid reg so everything is shifted!
# Warning: UC_DATA_REG should only be used in this file and the rest
#          should transparently use TEST_DATA_REG
TEST_RIMI_SHADOW_STACK_REG = RIMI_SHADOW_STACK_REG
assert RIMI_SHADOW_STACK_REG + 1 == UC_RISCV_REG_T3
UC_RIMI_SHADOW_STACK_REG = UC_RISCV_REG_T3

TEST_DATA_REG_D1 = RIMI_DATA_REG_D1
assert TEST_DATA_REG_D1 + 1 == UC_RISCV_REG_T4
UC_DATA_REG_D1 = UC_RISCV_REG_T4


RIMI_SHADOW_STACK_ADDRESS = 0x5000
DATA_D1_ADDRESS = 0xA000


class RIMIHandler(Handler):
    # Info on domains:
    # Start address, size!
    DOMAIN_INFO = {0: (DATA_ADDRESS, 0x4000), 1: (DATA_D1_ADDRESS, 0x1000)}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.current_domain = 0

    # Instruction Patching
    # \___________________

    def execute_new_instr(self, uc_emul, pc, old_instr, new_instr):
        # Write the new instruction in memory
        self.patch_instruction(uc_emul, pc, new_instr)
        # Writing to PC refreshes the emulation
        # uc_emul.reg_write(UC_RISCV_REG_PC, pc)
        # Execute it
        uc_emul.emu_start(begin=pc, until=pc + 4)
        # Repatch with the old instruction
        self.patch_instruction(uc_emul, pc, old_instr)

    def patch_instruction(self, uc_emul, address, instr):
        # Overwrite an instruction with a new one, refresh cache
        uc_emul.mem_write(address, instr)
        # Refresh the cache
        uc_emul.ctl_remove_cache(address, address + 4)
        # If the whole tb needs to be refreshed:
        # tb = uc_emul.ctl_request_cache(pc)
        # uc_emul.ctl_remove_cache(pc, pc + 4)

    # Info extraction
    # \______________

    def generate_new_load(self, instr, method):
        # Extract info
        rd = self.disasm.extract_rd(instr)
        rs1 = self.disasm.extract_rs1(instr)
        imm = self.disasm.extract_imm_i(instr)
        # Generate bytes from given constructor
        return method(rd=rd, rs1=rs1, imm=imm).generate_bytes()

    def generate_new_store(self, instr, method):
        # Extract info
        rs1 = self.disasm.extract_rs1(instr)
        rs2 = self.disasm.extract_rs2(instr)
        imm = self.disasm.extract_imm_s(instr)
        # Generate bytes from given constructor
        return method(rs1=rs1, rs2=rs2, imm=imm).generate_bytes()

    # Shadow stack instructions
    # \________________________

    def handle_sws(self, uc_emul, *args, **kwargs):
        # Get the shadow stack pointer
        ss_address = uc_emul.reg_read(UC_RIMI_SHADOW_STACK_REG)
        # Get the return address
        return_address = uc_emul.reg_read(UC_RISCV_REG_RA)
        # Write the return address to the shadow stack
        uc_emul.mem_write(ss_address, int_to_bytes64(return_address))

    def handle_lws(self, uc_emul, *args, **kwargs):
        # Get the shadow stack pointer
        ss_address = uc_emul.reg_read(UC_RIMI_SHADOW_STACK_REG)
        # Read the return address from the shadow stack
        return_address = uc_emul.mem_read(ss_address, 8)
        # Write the return address in RA
        uc_emul.reg_write(UC_RISCV_REG_RA, bytes_to_int(return_address))

    # Load duplicate instructions
    # \__________________________

    def handle_lb1(self, uc_emul, pc, instr):
        new_instr = self.generate_new_load(instr, IInstruction.lb)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_lbu1(self, uc_emul, pc, instr):
        new_instr = self.generate_new_load(instr, IInstruction.lbu)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_lh1(self, uc_emul, pc, instr):
        new_instr = self.generate_new_load(instr, IInstruction.lh)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_lhu1(self, uc_emul, pc, instr):
        new_instr = self.generate_new_load(instr, IInstruction.lhu)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_lw1(self, uc_emul, pc, instr):
        new_instr = self.generate_new_load(instr, IInstruction.lw)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_lwu1(self, uc_emul, pc, instr):
        new_instr = self.generate_new_load(instr, IInstruction.lwu)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_ld1(self, uc_emul, pc, instr):
        new_instr = self.generate_new_load(instr, IInstruction.ld)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    # Store duplicate instructions
    # \___________________________

    def handle_sb1(self, uc_emul, pc, instr):
        new_instr = self.generate_new_store(instr, SInstruction.sb)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_sh1(self, uc_emul, pc, instr):
        new_instr = self.generate_new_store(instr, SInstruction.sh)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_sw1(self, uc_emul, pc, instr):
        new_instr = self.generate_new_store(instr, SInstruction.sw)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_sd1(self, uc_emul, pc, instr):
        new_instr = self.generate_new_store(instr, SInstruction.sd)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    # Domain change instructions
    # \_________________________

    def handle_jalx(self, uc_emul, instr):
        pass

    def handle_jalrx(self, uc_emul, instr):
        pass


@pytest.fixture
def rimi_disasm_setup():
    disassembler = Disassembler(INSTRUCTIONS_INFO | RIMI_INSTRUCTIONS_INFO)
    return disassembler


@pytest.fixture
def rimi_handler_setup(rimi_disasm_setup):
    return RIMIHandler(rimi_disasm_setup)
