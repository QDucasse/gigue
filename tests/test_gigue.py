import pytest
from capstone import CS_ARCH_RISCV
from capstone import CS_MODE_RISCV64
from capstone import Cs
from unicorn import Uc
from unicorn.unicorn_const import UC_ARCH_RISCV
from unicorn.unicorn_const import UC_MODE_RISCV64

from gigue.constants import CALLER_SAVED_REG
from gigue.disassembler import Disassembler
from gigue.gigue import Gigue
from gigue.instructions import IInstruction

# =================================
#            Constants
# =================================

disassembler = Disassembler()
INTERPRETER_START_ADDRESS = 0x1000
JIT_START_ADDRESS = 0x3000
END_ADDRESS = 0xFFF0
cap_disasm = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)

# =================================
#          Filling tests
# =================================


@pytest.mark.parametrize("jit_elements_nb", [8, 10, 20, 30, 50, 100])
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
@pytest.mark.parametrize("pics_ratio", [0])
def test_fill_jit_code(jit_elements_nb, method_max_size, pics_ratio):
    gigue = Gigue(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_elements_nb=jit_elements_nb, method_max_size=method_max_size, method_max_calls=5,
        pics_method_max_size=30, pics_max_cases=5, pics_methods_max_calls=5, pics_ratio=pics_ratio
    )
    gigue.fill_jit_code()
    assert len(gigue.jit_methods) == jit_elements_nb


@pytest.mark.parametrize("jit_elements_nb", [8, 10, 20, 30, 50, 100])
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
@pytest.mark.parametrize("pics_ratio", [0])
def test_fill_interpretation_loop(jit_elements_nb, method_max_size, pics_ratio):
    gigue = Gigue(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_elements_nb=jit_elements_nb, method_max_size=method_max_size, method_max_calls=5,
        pics_method_max_size=30, pics_max_cases=5, pics_methods_max_calls=5, pics_ratio=pics_ratio
    )
    gigue.fill_jit_code()
    gigue.fill_interpretation_loop()
    assert len(gigue.interpreter_calls) == jit_elements_nb
    for i, (jit_element, call_instruction) in enumerate(zip(gigue.jit_elements, gigue.interpreter_calls)):
        assert call_instruction[0].name == "auipc"
        assert call_instruction[1].name == "jalr"

# =================================
#         Generation tests
# =================================


@pytest.mark.parametrize("jit_elements_nb", [8, 10, 20, 30, 50, 100])
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
@pytest.mark.parametrize("pics_ratio", [0, 0.1, 0.2, 0.5])
def test_generate_jit_machine_code(jit_elements_nb, method_max_size, pics_ratio):
    gigue = Gigue(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_elements_nb=jit_elements_nb, method_max_size=method_max_size, method_max_calls=5,
        pics_method_max_size=30, pics_max_cases=5, pics_methods_max_calls=5, pics_ratio=pics_ratio
    )
    gigue.fill_jit_code()
    gigue.fill_interpretation_loop()
    gigue.generate_jit_machine_code()
    assert len(gigue.jit_machine_code) == jit_elements_nb
    # Add another assertion for PICs
    # for method in gigue.jit_machine_code:
    #     assert len(method) <= method_max_size


@pytest.mark.parametrize("jit_elements_nb", [8, 10, 20, 30, 50, 100])
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
@pytest.mark.parametrize("pics_ratio", [0, 0.1, 0.2, 0.5])
def test_generate_interpreter_machine_code(jit_elements_nb, method_max_size, pics_ratio):
    gigue = Gigue(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_elements_nb=jit_elements_nb, method_max_size=method_max_size, method_max_calls=5,
        pics_method_max_size=30, pics_max_cases=5, pics_methods_max_calls=5, pics_ratio=pics_ratio
    )
    gigue.fill_jit_code()
    gigue.fill_interpretation_loop()
    gigue.generate_jit_machine_code()
    gigue.generate_interpreter_machine_code()
    assert len(gigue.interpreter_calls) == jit_elements_nb
    for i, (jit_element, call_instruction) in enumerate(zip(gigue.jit_elements, gigue.interpreter_machine_code)):
        # print("{}: {} | {}".format(i, jit_element, call_instruction))
        # print("higho: {}, lowo: {}".format(hex(call_instruction[0].imm), hex(call_instruction[1].imm)))
        call_offset = disassembler.extract_call_offset(call_instruction)
        assert (gigue.interpreter_start_address + i * 8) + call_offset == jit_element.address


@pytest.mark.parametrize("jit_elements_nb", [8, 10, 20, 30, 50, 100])
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
@pytest.mark.parametrize("pics_ratio", [0, 0.1, 0.2, 0.5])
def test_generate_bytes(jit_elements_nb, method_max_size, pics_ratio):
    gigue = Gigue(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_elements_nb=jit_elements_nb, method_max_size=method_max_size, method_max_calls=5,
        pics_method_max_size=30, pics_max_cases=5, pics_methods_max_calls=5, pics_ratio=pics_ratio
    )
    gigue.fill_jit_code()
    gigue.fill_interpretation_loop()
    gigue.generate_jit_machine_code()
    gigue.generate_interpreter_machine_code()
    gigue.generate_jit_bytes()
    gigue.generate_interpreter_bytes()
    assert len(gigue.jit_bytes) == len(gigue.jit_machine_code)
    assert len(gigue.interpreter_bytes) == len(gigue.interpreter_machine_code)

# =================================
#         Execution tests
# =================================


@pytest.mark.parametrize("jit_elements_nb", [10, 20, 50, 100, 200])
@pytest.mark.parametrize("method_max_size", [5, 10, 20, 50, 100, 200])
@pytest.mark.parametrize("pics_ratio", [0, 0.1, 0.2, 0.5])
def test_execute_generated_binaries(jit_elements_nb, method_max_size, pics_ratio):
    gigue = Gigue(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_elements_nb=jit_elements_nb, method_max_size=method_max_size, method_max_calls=5,
        pics_method_max_size=30, pics_max_cases=5, pics_methods_max_calls=5, pics_ratio=pics_ratio
    )
    gigue.fill_jit_code()
    gigue.fill_interpretation_loop()
    gigue.generate_jit_machine_code()
    gigue.generate_interpreter_machine_code()
    gigue.generate_jit_bytes()
    gigue.generate_interpreter_bytes()
    interpreter_binary = gigue.generate_interpreter_binary()
    # cap_disasm.disasm(interpreter_binary, INTERPRETER_START_ADDRESS)
    # Binary infos:
    # print("Interpreter binary: from {} to {} (length {})".format(
    #     hex(INTERPRETER_START_ADDRESS),
    #     hex(INTERPRETER_START_ADDRESS + len(interpreter_binary)),
    #     len(interpreter_binary)
    # ))
    # Capstone disasm:
    # for i in cap_disasm.disasm(interpreter_binary, INTERPRETER_START_ADDRESS):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    jit_binary = gigue.generate_jit_binary()
    # Binary infos:
    # print("JIT binary: from {} to {} (length {})".format(
    #     hex(JIT_START_ADDRESS),
    #     hex(JIT_START_ADDRESS + len(jit_binary)),
    #     len(jit_binary)
    # ))
    # Capstone disasm:
    # for i in cap_disasm.disasm(jit_binary, JIT_START_ADDRESS):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    uc_emul = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
    uc_emul.mem_map(INTERPRETER_START_ADDRESS, 2 * 1024 * 1024)
    # Fill memory with nops up to BEEC by default
    for addr in range(JIT_START_ADDRESS, END_ADDRESS + 4, 4):
        uc_emul.mem_write(addr, IInstruction.nop().generate_bytes())
    # Zero out registers
    for reg in CALLER_SAVED_REG:
        uc_emul.reg_write(reg, 0)
    uc_emul.mem_write(INTERPRETER_START_ADDRESS, interpreter_binary)
    uc_emul.mem_write(JIT_START_ADDRESS, jit_binary)
    uc_emul.emu_start(INTERPRETER_START_ADDRESS, INTERPRETER_START_ADDRESS + len(interpreter_binary))
    uc_emul.emu_stop()
