from math import ceil, trunc
from typing import Union
import pytest

from gigue.exceptions import WrongAddressException
from gigue.generator import Generator, TrampolineGenerator
from gigue.helpers import poisson_chernoff_bound
from gigue.method import Method
from gigue.pic import PIC
from tests.conftest import (
    INTERPRETER_START_ADDRESS,
    JIT_START_ADDRESS,
    RET_ADDRESS,
    TEST_DATA_REG,
    TEST_DATA_SIZE,
    cap_disasm_bytes,
    check_size,
)

# =================================
#          Initialization
# =================================


def test_not_implemented():
    with pytest.raises(WrongAddressException):
        Generator(
            jit_start_address=0,
            interpreter_start_address=INTERPRETER_START_ADDRESS,
            jit_size=500,
            jit_nb_methods=10,
            method_variation_mean=0.2,
            method_variation_stdev=0.1,
            call_occupation_mean=0.2,
            call_occupation_stdev=0.1,
            call_depth_mean=2,
            pics_max_cases=2,
            pics_ratio=0.5,
        )


# =================================
#          Filling tests
# =================================


def check_method_bounds(
    method,
    method_variation_mean,
    method_variation_stdev,
    call_occupation_mean,
    call_occupation_stdev,
    call_depth_mean,
    call_size,
):
    # Check the bounds of method size
    max_deviation_size = method_variation_mean + 4 * method_variation_stdev
    assert (
        round(method.body_size * (1 - max_deviation_size))
        <= method.body_size
        <= round(method.body_size * (1 + max_deviation_size))
    )
    # Check the bounds of call occupation
    max_deviation_calls = call_occupation_mean + 4 * call_occupation_stdev
    min_deviation_calls = call_occupation_mean - 4 * call_occupation_stdev
    max_call_nb = method.body_size // call_size
    if method.call_number > 0:
        assert (
            trunc(max_call_nb * min_deviation_calls)
            <= method.call_number
            <= ceil(max_call_nb * max_deviation_calls)
        )
    # Check the bounds of the call depth
    assert 0 <= method.call_depth <= poisson_chernoff_bound(call_depth_mean, 0.00001)


@pytest.mark.parametrize("jit_size", [100, 200, 500])
@pytest.mark.parametrize("jit_nb_methods", [10, 100])
@pytest.mark.parametrize("pics_ratio", [0, 0.5])
@pytest.mark.parametrize("call_depth_mean", [1, 2])
@pytest.mark.parametrize(
    "call_occupation_mean, call_occupation_stdev", [(0.2, 0.1), (0.5, 0.2)]
)
@pytest.mark.parametrize("pics_max_cases", [2, 5])
def test_fill_jit_code(
    jit_size,
    jit_nb_methods,
    pics_ratio,
    call_occupation_mean,
    call_occupation_stdev,
    call_depth_mean,
    pics_max_cases,
):
    generator = Generator(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_size=jit_size,
        jit_nb_methods=jit_nb_methods,
        method_variation_mean=0.2,
        method_variation_stdev=0.1,
        call_occupation_mean=call_occupation_mean,
        call_occupation_stdev=call_occupation_stdev,
        call_depth_mean=call_depth_mean,
        pics_max_cases=pics_max_cases,
        pics_ratio=pics_ratio,
    )
    generator.fill_jit_code()
    generator.patch_jit_calls()
    assert sum([elt.method_nb() for elt in generator.jit_elements]) == jit_nb_methods
    # Check call numbers and number of cases per PIC
    for elt in generator.jit_elements:
        if isinstance(elt, PIC):
            assert elt.case_number <= generator.pics_max_cases
            for method in elt.methods:
                check_method_bounds(
                    method=method,
                    method_variation_mean=generator.method_variation_mean,
                    method_variation_stdev=generator.method_variation_stdev,
                    call_occupation_mean=generator.call_occupation_mean,
                    call_occupation_stdev=generator.call_occupation_stdev,
                    call_depth_mean=generator.call_depth_mean,
                    call_size=generator.call_size,
                )
        elif isinstance(elt, Method):
            method = elt
            check_method_bounds(
                method=method,
                method_variation_mean=generator.method_variation_mean,
                method_variation_stdev=generator.method_variation_stdev,
                call_occupation_mean=generator.call_occupation_mean,
                call_occupation_stdev=generator.call_occupation_stdev,
                call_depth_mean=generator.call_depth_mean,
                call_size=generator.call_size,
            )


@pytest.mark.parametrize("jit_size", [100, 200, 500])
@pytest.mark.parametrize("jit_nb_methods", [10, 100])
@pytest.mark.parametrize("pics_ratio", [0, 0.2, 0.5])
def test_fill_interpretation_loop(jit_size, jit_nb_methods, pics_ratio):
    generator = Generator(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_size=jit_size,
        jit_nb_methods=jit_nb_methods,
        method_variation_mean=0.2,
        method_variation_stdev=0.1,
        call_occupation_mean=0.2,
        call_occupation_stdev=0.1,
        call_depth_mean=2,
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
    #                     disasm.extract_pc_relative_offset(mc_code[i + 1 : i + 3])
    #                     in elt_addresses
    #                 )
    #     elif disasm.get_instruction_name(instr) == "auipc":
    #         if disasm.get_instruction_name(mc_code[i + 1]) == "jalr":
    #             assert disasm.extract_pc_relative
    # _offset(mc_code[i : i + 2]) in elt_addresses


# TODO: Smoke test, add real testing hihi
@pytest.mark.parametrize("jit_size", [100, 200, 500])
@pytest.mark.parametrize("jit_nb_methods", [10, 100])
@pytest.mark.parametrize("pics_ratio", [0, 0.2, 0.5])
@pytest.mark.parametrize("call_depth_mean", [2, 4])
@pytest.mark.parametrize(
    "call_occupation_mean, call_occupation_stdev", [(0.2, 0.1), (0.4, 0.2)]
)
@pytest.mark.parametrize("pics_max_cases", [2, 5, 10])
def test_patch_calls(
    jit_size,
    jit_nb_methods,
    pics_ratio,
    call_depth_mean,
    call_occupation_mean,
    call_occupation_stdev,
    pics_max_cases,
):
    generator = Generator(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_size=jit_size,
        jit_nb_methods=jit_nb_methods,
        method_variation_mean=0.2,
        method_variation_stdev=0.1,
        call_occupation_mean=call_occupation_mean,
        call_occupation_stdev=call_occupation_stdev,
        call_depth_mean=call_depth_mean,
        pics_max_cases=pics_max_cases,
        pics_ratio=pics_ratio,
    )
    generator.fill_jit_code()
    generator.patch_jit_calls()
    generator.fill_interpretation_loop()


# =================================
#         Generation tests
# =================================


@pytest.mark.parametrize("jit_size", [100, 200, 500])
@pytest.mark.parametrize("jit_nb_methods", [10, 100])
@pytest.mark.parametrize("pics_ratio", [0, 0.2, 0.5])
def test_generate_interpreter_machine_code(jit_size, jit_nb_methods, pics_ratio):
    generator = Generator(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_size=jit_size,
        jit_nb_methods=jit_nb_methods,
        method_variation_mean=0.2,
        method_variation_stdev=0.1,
        call_occupation_mean=0.2,
        call_occupation_stdev=0.1,
        call_depth_mean=2,
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
    #     call_offset = disassembler.extract_pc_relative_offset(call_instruction)
    #     assert (
    #         generator.interpreter_start_address + method_count * 8 + pic_count * 12
    #     ) + call_offset == jit_element.address

    #     if is_pic:
    #         pic_count += 1
    #     else:
    #         method_count += 1


@pytest.mark.parametrize("jit_size", [200, 500])
@pytest.mark.parametrize("jit_nb_methods", [10, 100])
@pytest.mark.parametrize("pics_ratio", [0, 0.2, 0.5])
def test_generate_bytes(jit_size, jit_nb_methods, pics_ratio):
    generator = Generator(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_size=jit_size,
        jit_nb_methods=jit_nb_methods,
        method_variation_mean=0.2,
        method_variation_stdev=0.1,
        call_occupation_mean=0.2,
        call_occupation_stdev=0.1,
        call_depth_mean=2,
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


@pytest.mark.parametrize(
    (
        "jit_size, jit_nb_methods, pics_ratio, meth_var_mean, meth_var_stdev,"
        " call_occupation_mean, call_occupation_stdev, call_depth_mean"
    ),
    [
        (50, 5, 0, 0.2, 0.1, 0.2, 0.1, 1),
        (200, 10, 0.2, 0.4, 0.2, 0.4, 0.2, 2),
        (5000, 50, 0.5, 0.5, 0.2, 0.5, 0.2, 3),
    ],
)
def test_execute_generated_binaries(
    jit_size,
    jit_nb_methods,
    meth_var_mean,
    pics_ratio,
    meth_var_stdev,
    call_occupation_mean,
    call_occupation_stdev,
    call_depth_mean,
    cap_disasm_setup,
    handler_setup,
    uc_emul_full_setup,
):
    generator = Generator(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_size=jit_size,
        jit_nb_methods=jit_nb_methods,
        method_variation_mean=meth_var_mean,
        method_variation_stdev=meth_var_stdev,
        call_occupation_mean=call_occupation_mean,
        call_occupation_stdev=call_occupation_stdev,
        call_depth_mean=call_depth_mean,
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
    generator.generate_output_binary()
    generator.generate_data_binary()

    # Testing guard
    check_size(generator)

    # Capstone disasm:
    cap_disasm = cap_disasm_setup

    # Interpreter bin
    interpreter_binary = generator.generate_interpreter_binary()
    cap_disasm_bytes(cap_disasm, interpreter_binary, INTERPRETER_START_ADDRESS)
    # JIT bin
    jit_binary = generator.generate_jit_binary()
    cap_disasm_bytes(cap_disasm, jit_binary, JIT_START_ADDRESS)

    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(INTERPRETER_START_ADDRESS, interpreter_binary)
    uc_emul.mem_write(JIT_START_ADDRESS, jit_binary)

    # Handler
    handler = handler_setup
    handler.hook_instr_tracer(uc_emul)

    uc_emul.emu_start(INTERPRETER_START_ADDRESS, RET_ADDRESS)
    uc_emul.emu_stop()


@pytest.mark.parametrize(
    (
        "jit_size, jit_nb_methods, pics_ratio, meth_var_mean, meth_var_stdev,"
        " call_occupation_mean, call_occupation_stdev, call_depth_mean"
    ),
    [
        (50, 5, 0, 0.2, 0.1, 0.2, 0.1, 1),
        (200, 10, 0.2, 0.4, 0.2, 0.4, 0.2, 2),
        (5000, 50, 0.5, 0.5, 0.2, 0.5, 0.2, 3),
    ],
)
def test_execute_trampoline_generated_binaries(
    jit_size,
    jit_nb_methods,
    pics_ratio,
    meth_var_mean,
    meth_var_stdev,
    call_occupation_mean,
    call_occupation_stdev,
    call_depth_mean,
    cap_disasm_setup,
    handler_setup,
    uc_emul_full_setup,
):
    generator = TrampolineGenerator(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_size=jit_size,
        jit_nb_methods=jit_nb_methods,
        method_variation_mean=meth_var_mean,
        method_variation_stdev=meth_var_stdev,
        call_occupation_mean=call_occupation_mean,
        call_occupation_stdev=call_occupation_stdev,
        call_depth_mean=call_depth_mean,
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
    generator.generate_output_binary()
    generator.generate_data_binary()

    # Testing guard
    check_size(generator)

    # Capstone disasm:
    cap_disasm = cap_disasm_setup

    # Interpreter bin
    interpreter_binary = generator.generate_interpreter_binary()
    cap_disasm_bytes(cap_disasm, interpreter_binary, INTERPRETER_START_ADDRESS)
    # JIT bin
    jit_binary = generator.generate_jit_binary()
    cap_disasm_bytes(cap_disasm, jit_binary, JIT_START_ADDRESS)

    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(INTERPRETER_START_ADDRESS, interpreter_binary)
    uc_emul.mem_write(JIT_START_ADDRESS, jit_binary)

    # Handler
    handler = handler_setup
    handler.hook_instr_tracer(uc_emul)

    uc_emul.emu_start(INTERPRETER_START_ADDRESS, RET_ADDRESS)
    uc_emul.emu_stop()
