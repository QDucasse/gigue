import pytest
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, Cs
from conftest import DATA_ADDRESS, TEST_DATA_REG, TEST_DATA_SIZE, UC_DATA_REG
from unicorn import Uc
from unicorn.riscv_const import UC_RISCV_REG_RA, UC_RISCV_REG_SP
from unicorn.unicorn_const import UC_ARCH_RISCV, UC_MODE_RISCV64

from gigue.constants import CALLER_SAVED_REG
from gigue.disassembler import Disassembler
from gigue.exceptions import WrongAddressException
from gigue.generator import Generator
from gigue.instructions import IInstruction
from gigue.method import Method
from gigue.pic import PIC

# =================================
#            Constants
# =================================

disassembler = Disassembler()
INTERPRETER_START_ADDRESS = 0x1000
JIT_START_ADDRESS = 0x3000
STACK_ADDRESS = 0x10000
END_ADDRESS = 0xFFF0
cap_disasm = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)


# =================================
#          Initialization
# =================================


def test_not_implemented():
    with pytest.raises(WrongAddressException):
        Generator(
            jit_start_address=0,
            interpreter_start_address=INTERPRETER_START_ADDRESS,
            jit_elements_nb=10,
            method_max_size=10,
            max_call_depth=2,
            max_call_nb=2,
            pics_method_max_size=10,
            pics_max_cases=2,
            pics_ratio=0.5,
        )


# =================================
#          Filling tests
# =================================


@pytest.mark.parametrize("jit_elements_nb", [10, 100])
@pytest.mark.parametrize("method_max_size", [5, 20, 100])
@pytest.mark.parametrize("pics_ratio", [0, 0.5])
@pytest.mark.parametrize("max_call_depth", [2, 5, 10])
@pytest.mark.parametrize("max_call_nb", [2, 5, 10])
@pytest.mark.parametrize("pics_max_cases", [2, 5, 10])
def test_fill_jit_code(
    jit_elements_nb,
    method_max_size,
    pics_ratio,
    max_call_depth,
    max_call_nb,
    pics_max_cases,
):
    generator = Generator(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_elements_nb=jit_elements_nb,
        method_max_size=method_max_size,
        max_call_depth=max_call_depth,
        max_call_nb=max_call_nb,
        pics_method_max_size=method_max_size,
        pics_max_cases=pics_max_cases,
        pics_ratio=pics_ratio,
    )
    generator.fill_jit_code()
    generator.patch_jit_calls()
    assert len(generator.jit_elements) == jit_elements_nb
    assert generator.pic_count + generator.method_count == jit_elements_nb
    # Check call numbers and number of cases per PIC
    for elt in generator.jit_elements:
        if isinstance(elt, PIC):
            assert elt.case_number <= generator.pics_max_cases
            for method in elt.methods:
                assert method.call_number <= generator.max_call_nb
        elif isinstance(elt, Method):
            assert elt.call_number <= generator.max_call_nb
    # Check call depths
    for i in generator.call_depth_dict.keys():
        for method in generator.call_depth_dict[i]:
            assert 0 <= method.call_depth <= generator.max_call_depth


@pytest.mark.parametrize("jit_elements_nb", [5, 20, 100])
@pytest.mark.parametrize("method_max_size", [5, 20, 100])
@pytest.mark.parametrize("pics_ratio", [0, 0.2, 0.5])
def test_fill_interpretation_loop(jit_elements_nb, method_max_size, pics_ratio):
    generator = Generator(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_elements_nb=jit_elements_nb,
        method_max_size=method_max_size,
        max_call_depth=5,
        max_call_nb=5,
        pics_method_max_size=30,
        pics_max_cases=5,
        pics_ratio=pics_ratio,
    )
    generator.fill_jit_code()
    generator.patch_jit_calls()
    generator.fill_interpretation_loop()
    assert (
        len(generator.interpreter_instructions)
        == 2 * generator.method_count
        + 3 * generator.pic_count
        + Generator.INT_PROLOGUE_SIZE
        + Generator.INT_EPILOGUE_SIZE
    )

    # TODO: Monitor calls
    # disasm = disasm_setup
    # elt_addresses = [elt.address for elt in generator.jit_elements]
    # mc_code = generator.generate_interpreter_machine_code()
    # for i, instr in enumerate(
    #     mc_code[
    #         generator.interpreter_prologue_size : -generator.interpreter_epilogue_size
    #     ]
    # ):
    #     print(instr)
    #     if disasm.get_instruction_name(instr) == "addi":
    #         if disasm.get_instruction_name(mc_code[i + 1]) == "auipc":
    #             if disasm.get_instruction_name(mc_code[i + 2]) == "jalr":
    #                 assert (
    #                     disasm.extract_call_offset(mc_code[i + 1 : i + 3])
    #                     in elt_addresses
    #                 )
    #     elif disasm.get_instruction_name(instr) == "auipc":
    #         if disasm.get_instruction_name(mc_code[i + 1]) == "jalr":
    #             assert disasm.extract_call_offset(mc_code[i : i + 2]) in elt_addresses


# TODO: Smoke test, add real testing hihi
@pytest.mark.parametrize("jit_elements_nb", [20, 100])
@pytest.mark.parametrize("method_max_size", [20, 100])
@pytest.mark.parametrize("pics_ratio", [0, 0.2, 0.5])
@pytest.mark.parametrize("max_call_depth", [2, 5, 10])
@pytest.mark.parametrize("max_call_nb", [2, 5, 10])
@pytest.mark.parametrize("pics_max_cases", [2, 5, 10])
def test_patch_calls(
    jit_elements_nb,
    method_max_size,
    pics_ratio,
    max_call_depth,
    max_call_nb,
    pics_max_cases,
):
    generator = Generator(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_elements_nb=jit_elements_nb,
        method_max_size=method_max_size,
        max_call_depth=max_call_depth,
        max_call_nb=max_call_nb,
        pics_method_max_size=method_max_size,
        pics_max_cases=pics_max_cases,
        pics_ratio=pics_ratio,
    )
    generator.fill_jit_code()
    generator.patch_jit_calls()
    generator.fill_interpretation_loop()


# =================================
#         Generation tests
# =================================


@pytest.mark.parametrize("jit_elements_nb", [5, 20, 100])
@pytest.mark.parametrize("method_max_size", [5, 20, 100])
@pytest.mark.parametrize("pics_ratio", [0, 0.2, 0.5])
def test_generate_interpreter_machine_code(
    jit_elements_nb, method_max_size, pics_ratio
):
    generator = Generator(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_elements_nb=jit_elements_nb,
        method_max_size=method_max_size,
        max_call_depth=5,
        max_call_nb=5,
        pics_method_max_size=30,
        pics_max_cases=5,
        pics_ratio=pics_ratio,
    )
    generator.fill_jit_code()
    generator.patch_jit_calls()
    generator.fill_interpretation_loop()
    generator.generate_jit_machine_code()
    generator.generate_interpreter_machine_code()
    assert (
        len(generator.interpreter_instructions)
        == 2 * generator.method_count
        + 3 * generator.pic_count
        + Generator.INT_PROLOGUE_SIZE
        + Generator.INT_EPILOGUE_SIZE
    )
    # TODO: Rework with flattened
    # pic_count = 0
    # method_count = 0
    # for jit_element, call_instruction in zip(
    #     generator.jit_elements, generator.interpreter_machine_code
    # ):
    #     print("{}: {} | {}".format(i, jit_element, call_instruction))
    #     print(
    #         "higho: {}, lowo: {}".format(
    #             hex(call_instruction[0].imm), hex(call_instruction[1].imm)
    #         )
    #     )
    #     is_pic = False
    #     if len(call_instruction) == 3:  # pic with 3 instructions
    #         call_instruction = call_instruction[1:]
    #         is_pic = True
    #     call_offset = disassembler.extract_call_offset(call_instruction)
    #     assert (
    #         generator.interpreter_start_address + method_count * 8 + pic_count * 12
    #     ) + call_offset == jit_element.address

    #     if is_pic:
    #         pic_count += 1
    #     else:
    #         method_count += 1


@pytest.mark.parametrize("jit_elements_nb", [5, 20, 100])
@pytest.mark.parametrize("method_max_size", [5, 20, 100])
@pytest.mark.parametrize("pics_ratio", [0, 0.2, 0.5])
def test_generate_bytes(jit_elements_nb, method_max_size, pics_ratio):
    generator = Generator(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_elements_nb=jit_elements_nb,
        method_max_size=method_max_size,
        max_call_depth=5,
        max_call_nb=5,
        pics_method_max_size=30,
        pics_max_cases=5,
        pics_ratio=pics_ratio,
    )
    generator.fill_jit_code()
    generator.patch_jit_calls()
    generator.fill_interpretation_loop()
    generator.generate_jit_machine_code()
    generator.generate_interpreter_machine_code()
    generator.generate_jit_bytes()
    generator.generate_interpreter_bytes()
    assert len(generator.jit_bytes) == len(generator.jit_machine_code)
    assert len(generator.interpreter_bytes) == len(generator.interpreter_machine_code)


# =================================
#         Execution tests
# =================================


@pytest.mark.parametrize("jit_elements_nb", [5, 20, 100, 200])
@pytest.mark.parametrize("method_max_size", [5, 20, 50])
@pytest.mark.parametrize("pics_ratio", [0, 0.2, 0.5])
def test_execute_generated_binaries(
    jit_elements_nb, method_max_size, pics_ratio, cap_disasm_setup
):
    generator = Generator(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_elements_nb=jit_elements_nb,
        method_max_size=method_max_size,
        max_call_depth=5,
        max_call_nb=5,
        pics_method_max_size=method_max_size,
        pics_max_cases=2,
        pics_ratio=pics_ratio,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
    )
    generator.fill_jit_code()
    generator.patch_jit_calls()
    generator.fill_interpretation_loop()
    generator.generate_jit_machine_code()
    generator.generate_interpreter_machine_code()
    generator.generate_jit_bytes()
    generator.generate_interpreter_bytes()
    interpreter_binary = generator.generate_interpreter_binary()
    # Binary infos:
    # print(
    #     "Interpreter binary: from {} to {} (length {})".format(
    #         hex(INTERPRETER_START_ADDRESS),
    #         hex(INTERPRETER_START_ADDRESS + len(interpreter_binary)),
    #         len(interpreter_binary),
    #     )
    # )
    # Capstone disasm:
    # cap_disasm = cap_disasm_setup
    # for i in cap_disasm.disasm(interpreter_binary, INTERPRETER_START_ADDRESS):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    jit_binary = generator.generate_jit_binary()
    # Binary infos:
    # print(
    #     "JIT binary: from {} to {} (length {})".format(
    #         hex(JIT_START_ADDRESS),
    #         hex(JIT_START_ADDRESS + len(jit_binary)),
    #         len(jit_binary),
    #     )
    # )
    # Capstone disasm:
    # for i in cap_disasm.disasm(jit_binary, JIT_START_ADDRESS):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    data_binary = generator.generate_data_binary()
    uc_emul = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
    uc_emul.mem_map(INTERPRETER_START_ADDRESS, 2 * 1024 * 1024)
    # Fill memory with nops up to END_ADDRESS
    for addr in range(JIT_START_ADDRESS, END_ADDRESS + 4, 4):
        uc_emul.mem_write(addr, IInstruction.nop().generate_bytes())
    # Zero out registers
    for reg in CALLER_SAVED_REG:
        uc_emul.reg_write(reg, 0)
    # Write STACK ADDRESS in SP and END_ADDRESS in RA
    uc_emul.reg_write(UC_RISCV_REG_SP, STACK_ADDRESS)
    uc_emul.reg_write(UC_RISCV_REG_RA, END_ADDRESS)
    # Write the DATA_ADDRESS in DATA_REG
    uc_emul.reg_write(UC_DATA_REG, DATA_ADDRESS)
    uc_emul.mem_write(INTERPRETER_START_ADDRESS, interpreter_binary)
    uc_emul.mem_write(JIT_START_ADDRESS, jit_binary)
    uc_emul.mem_write(DATA_ADDRESS, data_binary)
    uc_emul.emu_start(INTERPRETER_START_ADDRESS, END_ADDRESS)
    # instrument_execution(uc_emul)
    # instrument_stack(uc_emul)
    uc_emul.emu_stop()
