import logging

import pytest
from unicorn.riscv_const import (
    UC_RISCV_REG_PC,
    UC_RISCV_REG_RA,
    UC_RISCV_REG_SP,
    UC_RISCV_REG_T3,
)

from gigue.constants import INSTRUCTIONS_INFO
from gigue.disassembler import Disassembler
from gigue.helpers import int_to_bytes32
from gigue.instructions import IInstruction, SInstruction
from gigue.rimi.rimi_constants import RIMI_INSTRUCTIONS_INFO, RIMI_SSP_REG
from tests.conftest import (
    ADDRESS,
    DATA_ADDRESS,
    INTERPRETER_START_ADDRESS,
    JIT_START_ADDRESS,
    STACK_ADDRESS,
    UC_CALL_TMP_REG,
    UC_TEST_MEM_SIZE,
    Handler,
)

logger = logging.getLogger("gigue")

# Check for correct test data reg and shadow stack reg, config vs unicorn one
# Note: Unicorn's 0 is the code for invalid reg so everything is shifted!
# Warning: UC_DATA_REG should only be used in this file and the rest
#          should transparently use TEST_DATA_REG
TEST_RIMI_SSP_REG = RIMI_SSP_REG
assert RIMI_SSP_REG + 1 == UC_RISCV_REG_T3
UC_RIMI_SSP_REG = UC_RISCV_REG_T3


# The memory layout is the following:
# _________________________________
#
#    interpreter zone/domain 0
#
#               CODE
#    (DATA) (unused by the interpreter)
#    (STACK) (unused because no external
#                  calls apart from JIT)
# __________________________________
# __________________________________
#
#        JIT zone/domain 1
#
#               CODE
#               DATA
# __________________________________
# __________________________________
#
#     Shadow Stack zone/domain 2
#
#              STACK
# __________________________________

RIMI_SHADOW_STACK_MAX_SIZE = 100 * 8  # 100 addresses!
RIMI_SHADOW_STACK_ADDRESS = STACK_ADDRESS + RIMI_SHADOW_STACK_MAX_SIZE

MAX_ADDRESS = ADDRESS + UC_TEST_MEM_SIZE
D0_ADDRESS = INTERPRETER_START_ADDRESS
D1_ADDRESS = JIT_START_ADDRESS
D2_ADDRESS = RIMI_SHADOW_STACK_ADDRESS - RIMI_SHADOW_STACK_MAX_SIZE

DATA_D1_ADDRESS = DATA_ADDRESS

D0_SIZE = D1_ADDRESS - D0_ADDRESS
D1_SIZE = D2_ADDRESS - D1_ADDRESS
D2_SIZE = RIMI_SHADOW_STACK_MAX_SIZE


class WrongDomainException(Exception):
    """
    Raised when an instruction is trying to execute in an incorrect domain.
    """

    pass


class DomainAccessException(Exception):
    """
    Raised when an instruction tries to access an address outside of its domain.
    """

    pass


class RIMIHandler(Handler):
    # Info on domains:
    # Start address, size!
    DOMAIN_INFO = {
        0: (D0_ADDRESS, D0_SIZE),
        1: (D1_ADDRESS, D1_SIZE),
        2: (D2_ADDRESS, D2_SIZE),
    }

    # Instructions and their domain:
    INSTRUCTIONS_DOMAIN = {
        "lb1": 1,
        "lbu1": 1,
        "lh1": 1,
        "lhu1": 1,
        "lw1": 1,
        "lwu1": 1,
        "ld1": 1,
        "sb1": 1,
        "sh1": 1,
        "sw1": 1,
        "sd1": 1,
        "lst": 2,
        "sst": 2,
        "chdom": 0,
        "retdom": 1,
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.current_domain = 0

    # Domain Checking
    # \______________

    def check_domain(self, instr_name):
        domain = RIMIHandler.INSTRUCTIONS_DOMAIN[instr_name]
        # ensure current_domain == domain
        if self.current_domain != domain:
            raise WrongDomainException(
                f"Instruction {instr_name} should be executing in domain"
                f" {domain} (currently {self.current_domain})"
            )
        return domain

    def check_address_in_domain(self, addr, domain):
        domain_begin, domain_size = RIMIHandler.DOMAIN_INFO[domain]
        # ensure domain_begin <= addr <= domain_begin + domain_size
        if addr < domain_begin or addr > domain_begin + domain_size:
            raise DomainAccessException(
                f"Domain {domain} only has access to address range"
                f" {hex(domain_begin)}-{hex(domain_begin + domain_size)}"
                f" (trying to access {hex(addr)})"
            )

    def check_load_access(self, uc_emul, instr):
        # Info extraction
        instr_name = self.disasm.get_instruction_info(instr).name
        rs1 = self.disasm.extract_rs1(instr)
        imm = self.disasm.extract_imm_i(instr)
        addr_rs1 = uc_emul.reg_read(rs1 + 1)
        # Checks
        domain = self.check_domain(instr_name)
        self.check_address_in_domain(addr_rs1 + imm, domain)

    def check_store_access(self, uc_emul, instr):
        # Info extraction
        instr_name = self.disasm.get_instruction_info(instr).name
        rs1 = self.disasm.extract_rs1(instr)
        imm = self.disasm.extract_imm_s(instr)
        addr_rs1 = uc_emul.reg_read(rs1 + 1)
        # Checks
        domain = self.check_domain(instr_name)
        self.check_address_in_domain(addr_rs1 + imm, domain)

    def check_domain_change(self, uc_emul, instr):
        # Info extraction
        instr_name = self.disasm.get_instruction_info(instr).name
        rs1 = self.disasm.extract_rs1(instr)
        imm = self.disasm.extract_imm_i(instr)
        addr_rs1 = uc_emul.reg_read(rs1 + 1)
        # Checks
        # Note: the trick abs(domain - 1) ensures the resulting domain
        # is 1 if it was 0 and 0 if it was 1
        domain = self.check_domain(instr_name)
        self.check_address_in_domain(addr_rs1 + imm, abs(domain - 1))

    # Instruction Patching
    # \___________________

    # Note: The patching and emulation use the method described here:
    # - https://github.com/unicorn-engine/unicorn/wiki/FAQ#editing-an-instruction-
    # doesnt-take-effecthooks-added-during-emulation-are-not-called
    # and in more details in the github issue:
    # - https://github.com/unicorn-engine/unicorn/issues/1561

    def execute_new_instr(self, uc_emul, pc, old_instr, new_instr):
        # Write the new instruction in memory and refresh tb
        self.patch_instruction(uc_emul, pc, new_instr)

        # Writing to PC relaunches the emulation WITHOUT quitting uc_emu_start!!
        # uc_emul.reg_write(UC_RISCV_REG_PC, pc)
        # Note: This would work if there was no need to RE-patch right after

        # Launch the emulation of the patched instruction alone
        uc_emul.emu_start(begin=pc, until=0, count=1)
        uc_emul.emu_stop()
        # Rewrite the old instruction in memory and refresh tb
        self.patch_instruction(uc_emul, pc, old_instr)

    def patch_instruction(self, uc_emul, address, instr):
        # Overwrite an instruction with a new one, refresh cache
        uc_emul.mem_write(address, instr)
        # Refresh the cache
        uc_emul.ctl_remove_cache(address, address + 4)
        # If the whole tb needs to be refreshed:
        # tb = uc_emul.ctl_request_cache(pc)
        # uc_emul.ctl_remove_cache(pc, pc + tb.size)

    # Info extraction
    # \______________

    def generate_new_iinstr(self, instr, method):
        # Extract info
        rd = self.disasm.extract_rd(instr)
        rs1 = self.disasm.extract_rs1(instr)
        imm = self.disasm.extract_imm_i(instr)
        # Generate bytes from given constructor
        logger.debug(f">>> Generated replacement {method.__name__} {rd}, {imm}({rs1})")
        return method(rd=rd, rs1=rs1, imm=imm).generate_bytes()

    def generate_new_sinstr(self, instr, method):
        # Extract info
        rs1 = self.disasm.extract_rs1(instr)
        rs2 = self.disasm.extract_rs2(instr)
        imm = self.disasm.extract_imm_s(instr)
        # Generate bytes from given constructor
        logger.debug(f">>> Generated replacement {method.__name__} {rs2}, {imm}({rs1})")
        return method(rs1=rs1, rs2=rs2, imm=imm).generate_bytes()

    # Shadow stack instructions
    # \________________________

    def handle_sst(self, uc_emul, pc, instr):
        logger.debug(">>> Handling sst")
        # Change domain and save previous one
        previous_domain = self.current_domain
        self.current_domain = 2
        # Check store access
        self.check_store_access(uc_emul=uc_emul, instr=instr)
        # Restore domain (note: done here because the next lines resume the execution)
        self.current_domain = previous_domain
        # Execute the new instruction
        new_instr = self.generate_new_sinstr(instr, SInstruction.sd)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_lst(self, uc_emul, pc, instr):
        logger.debug(">>> Handling lst")
        # Change domain and save previous one
        previous_domain = self.current_domain
        self.current_domain = 2
        # Check the load access
        self.check_load_access(uc_emul=uc_emul, instr=instr)
        # Restore domain (note: done here because the next lines resume the execution)
        self.current_domain = previous_domain
        # Execute the new instruction
        new_instr = self.generate_new_iinstr(instr, IInstruction.ld)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    # Load duplicate instructions
    # \__________________________

    def handle_lb1(self, uc_emul, pc, instr):
        logger.debug(">>> Handling lb1")
        self.check_load_access(uc_emul=uc_emul, instr=instr)
        new_instr = self.generate_new_iinstr(instr, IInstruction.lb)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_lbu1(self, uc_emul, pc, instr):
        logger.debug(">>> Handling lbu1")
        self.check_load_access(uc_emul=uc_emul, instr=instr)
        new_instr = self.generate_new_iinstr(instr, IInstruction.lbu)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_lh1(self, uc_emul, pc, instr):
        logger.debug(">>> Handling lh1")
        self.check_load_access(uc_emul=uc_emul, instr=instr)
        new_instr = self.generate_new_iinstr(instr, IInstruction.lh)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_lhu1(self, uc_emul, pc, instr):
        logger.debug(">>> Handling lhu1")
        self.check_load_access(uc_emul=uc_emul, instr=instr)
        new_instr = self.generate_new_iinstr(instr, IInstruction.lhu)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_lw1(self, uc_emul, pc, instr):
        logger.debug(">>> Handling lw1")
        self.check_load_access(uc_emul=uc_emul, instr=instr)
        new_instr = self.generate_new_iinstr(instr, IInstruction.lw)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_lwu1(self, uc_emul, pc, instr):
        logger.debug(">>> Handling lwu1")
        self.check_load_access(uc_emul=uc_emul, instr=instr)
        new_instr = self.generate_new_iinstr(instr, IInstruction.lwu)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_ld1(self, uc_emul, pc, instr):
        logger.debug(">>> Handling ld1")
        self.check_load_access(uc_emul=uc_emul, instr=instr)
        new_instr = self.generate_new_iinstr(instr, IInstruction.ld)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    # Store duplicate instructions
    # \___________________________

    def handle_sb1(self, uc_emul, pc, instr):
        logger.debug(">>> Handling sb1")
        self.check_store_access(uc_emul=uc_emul, instr=instr)
        new_instr = self.generate_new_sinstr(instr, SInstruction.sb)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_sh1(self, uc_emul, pc, instr):
        logger.debug(">>> Handling sh1")
        self.check_store_access(uc_emul=uc_emul, instr=instr)
        new_instr = self.generate_new_sinstr(instr, SInstruction.sh)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_sw1(self, uc_emul, pc, instr):
        self.check_store_access(uc_emul=uc_emul, instr=instr)
        new_instr = self.generate_new_sinstr(instr, SInstruction.sw)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_sd1(self, uc_emul, pc, instr):
        logger.debug(">>> Handling sd1")
        self.check_store_access(uc_emul=uc_emul, instr=instr)
        new_instr = self.generate_new_sinstr(instr, SInstruction.sd)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    # Domain change instructions
    # \_________________________

    def handle_chdom(self, uc_emul, pc, instr):
        logger.debug(">>> Handling chdom")
        # Check that we are in the correct domain to change
        self.check_domain_change(uc_emul=uc_emul, instr=instr)
        # Change domain (note: done here because the next lines resume the execution)
        self.current_domain = 1
        new_instr = self.generate_new_iinstr(instr, IInstruction.jalr)
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    def handle_retdom(self, uc_emul, pc, instr):
        logger.debug(">>> Handling retdom")
        # Check that we are in the correct domain to change
        self.check_domain_change(uc_emul=uc_emul, instr=instr)
        # Change domain (note: done here because the next lines resume the execution)
        self.current_domain = 0
        new_instr = self.generate_new_iinstr(instr, IInstruction.jalr)
        logger.debug(">>> Generated replacement ret")
        self.execute_new_instr(uc_emul, pc, int_to_bytes32(instr), new_instr)

    # Memory accesses checks
    # \_____________________

    # Note: While this solution would be the most elegant one,
    # the accesses use instructions that are replaced and would
    # always point to domain 0.

    # def check_mem_access(self, uc_emul, *args, **kwargs):
    #     pc = uc_emul.reg_read(UC_RISCV_REG_PC)
    #     instr = bytes_to_int(uc_emul.mem_read(pc, 4))
    #     instr_name = self.disasm.get_instruction_info(instr).name
    #     print(f">>> Catching {instr_name}")

    # def hook_mem_access(self, uc_emul):
    #     uc_emul.hook_add(UC_HOOK_MEM_VALID, self.check_mem_access, user_data=None)

    # Trace shadow stack reg
    # \_______________________

    def trace_reg(self, uc_emul, *args, **kwargs):
        # super().trace_reg(uc_emul)
        # Note: not overriding because it spans over multiple lines
        current_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
        current_sp = uc_emul.reg_read(UC_RISCV_REG_SP)
        current_ra = uc_emul.reg_read(UC_RISCV_REG_RA)
        current_ssp = uc_emul.reg_read(UC_RIMI_SSP_REG)
        current_call_tmp = uc_emul.reg_read(UC_CALL_TMP_REG)
        logger.debug(
            f">>> Tracing registers PC:{hex(current_pc)}, SP:{hex(current_sp)}, SSP:"
            f"{hex(current_ssp)}, RA:{hex(current_ra)}, CTMP:{hex(current_call_tmp)}"
        )


@pytest.fixture
def rimi_disasm_setup():
    disassembler = Disassembler(RIMI_INSTRUCTIONS_INFO | INSTRUCTIONS_INFO)
    return disassembler


@pytest.fixture
def rimi_handler_setup(rimi_disasm_setup: Disassembler):
    return RIMIHandler(rimi_disasm_setup)


@pytest.fixture
def rimi_uc_emul_full_setup(uc_emul_full_setup):
    uc_emul = uc_emul_full_setup
    # Setup the shadow stack pointer
    uc_emul.reg_write(UC_RIMI_SSP_REG, RIMI_SHADOW_STACK_ADDRESS)
    return uc_emul


def start_resumable_emulation(uc_emul, start_address, end_address):
    new_pc = start_address
    while new_pc != end_address:
        logger.debug(f">>>>>> NEW PC: {hex(new_pc)} END_ADDRESS: {hex(end_address)}")
        uc_emul.emu_stop()
        uc_emul.emu_start(new_pc, end_address)
        new_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
    uc_emul.emu_stop()
