import logging
import os
import random
import shutil
from datetime import datetime

import pytest
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, Cs
from unicorn import Uc
from unicorn.riscv_const import (
    UC_RISCV_REG_PC,
    UC_RISCV_REG_RA,
    UC_RISCV_REG_SP,
    UC_RISCV_REG_T1,
    UC_RISCV_REG_T6,
)
from unicorn.unicorn_const import (
    UC_ARCH_RISCV,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_MODE_RISCV64,
)

from gigue.constants import CALL_TMP_REG, CALLER_SAVED_REG, DATA_REG
from gigue.dataminer import Dataminer
from gigue.disassembler import Disassembler
from gigue.exceptions import UnknownInstructionException
from gigue.helpers import bytes_to_int

# =================================================
#                  Logging setup
# =================================================

TEST_LOG_DIR = "log/tests/"

if not os.path.exists(TEST_LOG_DIR):
    os.mkdir(TEST_LOG_DIR)

logger = logging.getLogger("gigue")

# Seed for reproducibility
SEED = bytes_to_int(os.urandom(16))
random.seed(SEED)


@pytest.fixture(scope="session", autouse=True)
def log_seed():
    logger.info(f"🌱 Seed for this test run: {SEED}")


@pytest.fixture(scope="function", autouse=True)
def disable_logger(caplog):
    caplog.set_level(logging.CRITICAL, logger="gigue")


@pytest.fixture(scope="function")
def log_trace(request, caplog):
    caplog.set_level(logging.DEBUG, logger="gigue")
    logger.info(f"Tracing test '{request.node.name}'  🚀")

    def fin():
        logger.info(f"Trace complete for test '{request.node.name}' 🏁")
        caplog.set_level(logging.CRITICAL, logger="gigue")

    request.addfinalizer(fin)


@pytest.fixture(scope="session", autouse=True)
def move_log_file(request):
    def fin():
        logger.info("Test run complete 🏁")
        # Set up name format  for test logfiles
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        test_log = f"{TEST_LOG_DIR}test_run_{timestamp}.log"
        shutil.copy("log/gigue.log", test_log)
        # Keep only 10 newest files
        log_files = [file for file in os.listdir(TEST_LOG_DIR) if "test_run" in file]
        full_paths = [os.path.join(TEST_LOG_DIR, file) for file in log_files]
        full_paths.sort(key=os.path.getmtime, reverse=True)
        for file in full_paths[9:]:
            os.remove(file)

    request.addfinalizer(fin)


# =================================================
#    Disassembler/Capstone setup and utilities
# =================================================


class IncorrectSizeException(Exception):
    """
    Raised when the generated binaries are too big for the unit test framework
    and memory layout.
    """

    pass


class EmptyBinaryException(Exception):
    """
    Raised when the generator has not yet generated binaries and is expected to test
    them.
    """

    pass


@pytest.fixture
def disasm_setup():
    disassembler = Disassembler()
    return disassembler


@pytest.fixture
def cap_disasm_setup():
    cap_disasm = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
    return cap_disasm


@pytest.fixture
def cap_disasm_custom_setup():
    cap_disasm = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
    # Enable skipdata to disassemble custom instructions
    cap_disasm.skipdata_setup = ("custom", disassemble_custom_callback, None)
    cap_disasm.skipdata = True
    return cap_disasm


def disassemble_custom_callback(buffer, size, offset, userdata):
    return 4


def cap_disasm_bytes(cap_disasm, binary, address):
    logger.debug(
        f"Binary: from {hex(address)} to {hex(address + len(binary)) } (length"
        f" {len(binary)})"
    )
    for i in cap_disasm.disasm(binary, address):
        logger.debug("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


def check_size(generator):
    # 0. Check that the binaries have been generated
    if any(
        len(binary) == 0
        for binary in [generator.jit_bin, generator.interpreter_bin, generator.data_bin]
    ):
        raise EmptyBinaryException(
            "Binaries not generated before checking size. Generate them with"
            " generate_output_binary() and generate_data_binary()"
        )

    logger.debug("Checking binary size before testing 📏")
    # 1. Check interpreter binary!
    #  \__ Check that int bin fits before the start of the jit bin
    if (
        INTERPRETER_START_ADDRESS + len(generator.interpreter_bytes * 4)
        > JIT_START_ADDRESS
    ):
        raise IncorrectSizeException(
            "Generated interpreter binary is too big for the test framework. Expecting"
            f" a max size of {hex(JIT_START_ADDRESS - INTERPRETER_START_ADDRESS)} and"
            f" got {hex(len(generator.interpreter_bytes * 4))}."
        )
    # 2. Check jit binary!
    #  \_ Check that jit bin fits before the start of the data bin
    if JIT_START_ADDRESS + len(generator.jit_bin) > DATA_ADDRESS:
        raise IncorrectSizeException(
            "Generated JIT binary is too big for the test framework."
            f" Expecting a max size of {hex(DATA_ADDRESS - JIT_START_ADDRESS)}"
            f" and got {hex(len(generator.jit_bin))}."
        )
    # 3. Check data binary!
    #  \_ Check that data bin fits before the stack
    if DATA_ADDRESS + len(generator.data_bin) > STACK_ADDRESS:
        raise IncorrectSizeException(
            "Generated data binary is too big for the test framework."
            f" Expecting a max size of {hex(STACK_ADDRESS - DATA_ADDRESS)}"
            f" and got {hex(len(generator.data_bin))}."
        )
    logger.debug("Binary compliant with tests memory structure ✅")
    logger.debug("Binary info:")
    logger.debug("Name | Start address | End address | Size")
    logger.debug("_____|_______________|_____________|_____")
    int_size = hex(INTERPRETER_START_ADDRESS + len(generator.interpreter_bytes * 4))
    logger.debug(
        f"INT  | {hex(INTERPRETER_START_ADDRESS):<{13}} |"
        f" {int_size:<{11}} |"
        f" {hex(len(generator.interpreter_bytes * 4))}"
    )
    logger.debug(
        f"JIT  | {hex(JIT_START_ADDRESS):<{13}} |"
        f" {hex(JIT_START_ADDRESS + len(generator.jit_bin)):<{11}} |"
        f" {hex(len(generator.jit_bin))}"
    )
    logger.debug(
        f"DAT  | {hex(DATA_ADDRESS):<{13}} |"
        f" {hex(DATA_ADDRESS + len(generator.data_bin)):<{11}} |"
        f" {hex(len(generator.data_bin))}"
    )


# =================================================
#                   Unicorn setup
# =================================================

# The memory layout is the following:
# _________________________________
#
#         interpreter zone
#
#               CODE
#    (DATA) (unused by the interpreter)
# __________________________________
# __________________________________
#
#             JIT zone
#
#               CODE
#               DATA
#
# __________________________________
# __________________________________
#
#               STACK
# __________________________________


# Address layout for tests
ADDRESS = 0x1000
STACK_ADDRESS = 0x30000
DATA_ADDRESS = 0x25000
UC_TEST_MEM_SIZE = 3 * 1024 * 1024
MAX_ADDRESS = ADDRESS + UC_TEST_MEM_SIZE

INTERPRETER_START_ADDRESS = 0x1000
JIT_START_ADDRESS = 0x6000
RET_ADDRESS = 0x5FFE

# Check for correct test data reg, config vs unicorn one
# Note: Unicorn's 0 is the code for invalid reg so everything is shifted!
# Warning: UC_DATA_REG should only be used in this file and the rest
#          should transparently use TEST_DATA_REG (apart from setting up unicorn)
TEST_DATA_REG = DATA_REG
assert TEST_DATA_REG + 1 == UC_RISCV_REG_T6
UC_DATA_REG = UC_RISCV_REG_T6

TEST_CALLER_SAVED_REG = [reg for reg in CALLER_SAVED_REG if reg != TEST_DATA_REG]
TEST_DATA_SIZE = 1024

# Check for correct test data reg, config vs unicorn one
# Note: Unicorn's 0 is the code for invalid reg so everything is shifted!
# Warning: UC_DATA_REG should only be used in this file and the rest should
#          transparently use TEST_CALL_TMP_REG (apart from setting up unicorn)
TEST_CALL_TMP_REG = CALL_TMP_REG
assert TEST_CALL_TMP_REG + 1 == UC_RISCV_REG_T1
UC_CALL_TMP_REG = UC_RISCV_REG_T1


@pytest.fixture
def uc_emul_setup():
    uc_emul = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
    uc_emul.mem_map(ADDRESS, UC_TEST_MEM_SIZE)
    return uc_emul


@pytest.fixture
def uc_emul_full_setup(uc_emul_setup):
    uc_emul = uc_emul_setup
    # Fill memory with nops up to RET_ADDRESS by default
    # Note: Takes A LOT of time... but maybe needed if we want to break by default
    # Zero out registers
    for reg in TEST_CALLER_SAVED_REG:
        uc_emul.reg_write(reg, 0)
    # Write data address in data reg
    uc_emul.reg_write(UC_DATA_REG, DATA_ADDRESS)
    # Write data to memory
    miner = Dataminer()
    data_bytes = miner.generate_data("iterative32", TEST_DATA_SIZE)
    uc_emul.mem_write(DATA_ADDRESS, data_bytes)
    # Write RET ADDRESS in RA
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    # Write STACK ADDRESS in SP
    uc_emul.reg_write(UC_RISCV_REG_SP, STACK_ADDRESS)
    return uc_emul


# =================================================
#                   Handler setup
# =================================================


class Handler:
    def __init__(self, disasm):
        self.disasm = disasm

    def handle_custom_instruction(self, uc_emul, intno, user_data):
        # When catching an exception, Unicorn already
        # forwarded the pc
        pc = uc_emul.reg_read(UC_RISCV_REG_PC) - 4
        instr = bytes_to_int(uc_emul.mem_read(pc, 4))
        try:
            # Extracts the instruction name
            instr_name = self.disasm.get_instruction_info(instr).name
            # Compare it to the one expected (if needed)
            if isinstance(user_data, str):
                logger.debug(f"Expecting {user_data}")
                assert instr_name == user_data
            # End of emulation if needed
            # end_emu = 0
            # if isinstance(user_data, int):
            #     end_emu = user_data
            # Call the handler if it exists
            try:
                handler_method = getattr(self.__class__, "handle_" + instr_name)
                handler_method(self, uc_emul, pc, instr)
            except AttributeError as err:
                # Otherwise stop the simulation and raise an exception
                uc_emul.emu_stop()
                raise AttributeError(
                    "Custom instruction callback has not been defined."
                ) from err
        except UnknownInstructionException:
            # Otherwise stop the simulation and raise an exception
            uc_emul.emu_stop()
            raise
        new_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
        if new_pc == pc:
            new_pc = pc + 4
        # Update the PC if the instruction handling went correctly
        uc_emul.reg_write(UC_RISCV_REG_PC, new_pc)

    # Tracing methods for instrumentation
    # \__________________________________

    def trace_instr(self, uc_emul, address, *args, **kwargs):
        instr = bytes_to_int(uc_emul.mem_read(address, 4))
        logger.debug(f">>> Tracing instruction {hex(instr)} at {hex(address)}")

    def trace_reg(self, uc_emul, *args, **kwargs):
        current_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
        current_sp = uc_emul.reg_read(UC_RISCV_REG_SP)
        current_ra = uc_emul.reg_read(UC_RISCV_REG_RA)
        current_call_tmp = uc_emul.reg_read(UC_CALL_TMP_REG)
        logger.debug(
            f">>> Tracing registers PC:{hex(current_pc)}, SP:{hex(current_sp)},"
            f" RA:{hex(current_ra)}, CTMP: {hex(current_call_tmp)}"
        )

    def trace_exception(self, uc_emul, intno, user_data):
        logger.debug(f">>> SEED {SEED}: Unicorn exception nb {intno}, tracing info")
        self.trace_reg(uc_emul)

    # Hook installers
    # \______________

    def hook_handler(self, uc_emul):
        uc_emul.hook_add(UC_HOOK_INTR, self.handle_custom_instruction, user_data=None)

    def hook_handler_expected(self, uc_emul, expected):
        uc_emul.hook_add(
            UC_HOOK_INTR, self.handle_custom_instruction, user_data=expected
        )

    def hook_handler_end_address(self, uc_emul, end_address):
        uc_emul.hook_add(
            UC_HOOK_INTR, self.handle_custom_instruction, user_data=end_address
        )

    def hook_instr_tracer(self, uc_emul):
        uc_emul.hook_add(UC_HOOK_CODE, self.trace_instr)

    def hook_reg_tracer(self, uc_emul):
        uc_emul.hook_add(UC_HOOK_CODE, self.trace_reg)

    def hook_exception_tracer(self, uc_emul):
        uc_emul.hook_add(UC_HOOK_INTR, self.trace_exception)


@pytest.fixture
def handler_setup(disasm_setup):
    return Handler(disasm_setup)
