from math import ceil, trunc

import pytest

from gigue.exceptions import WrongAddressException
from gigue.generator import Generator, TrampolineGenerator
from gigue.helpers import poisson_chernoff_bound, window
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
            pics_mean_case_nb=2,
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


@pytest.mark.parametrize(
    "jit_size, jit_nb_methods, pics_ratio",
    [
        (100, 10, 0),
        (200, 10, 0.2),
        (10000, 500, 0.5),
    ],
)
@pytest.mark.parametrize("call_depth_mean", [1, 2])
@pytest.mark.parametrize(
    "call_occupation_mean, call_occupation_stdev", [(0.2, 0.1), (0.5, 0.2)]
)
@pytest.mark.parametrize("pics_mean_case_nb", [1, 3])
@pytest.mark.parametrize("generator_class", [Generator, TrampolineGenerator])
def test_fill_jit_code(
    jit_size,
    jit_nb_methods,
    pics_ratio,
    call_occupation_mean,
    call_occupation_stdev,
    call_depth_mean,
    pics_mean_case_nb,
    generator_class,
):
    generator = generator_class(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_size=jit_size,
        jit_nb_methods=jit_nb_methods,
        method_variation_mean=0.2,
        method_variation_stdev=0.1,
        call_occupation_mean=call_occupation_mean,
        call_occupation_stdev=call_occupation_stdev,
        call_depth_mean=call_depth_mean,
        pics_mean_case_nb=pics_mean_case_nb,
        pics_ratio=pics_ratio,
    )
    generator.fill_jit_code()
    generator.patch_jit_calls()
    assert sum([elt.method_nb() for elt in generator.jit_elements]) == jit_nb_methods
    # Check call numbers and number of cases per PIC
    for elt in generator.jit_elements:
        if isinstance(elt, PIC):
            assert (
                elt.case_number
                <= poisson_chernoff_bound(generator.pics_mean_case_nb, 0.0001) + 1
            )
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


@pytest.mark.parametrize(
    "jit_size, jit_nb_methods,pics_ratio",
    [
        (100, 10, 0),
        (200, 10, 0.2),
        (10000, 500, 0.5),
    ],
)
def test_fill_interpretation_loop(jit_size, jit_nb_methods, pics_ratio, disasm_setup):
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
        pics_mean_case_nb=2,
        pics_ratio=pics_ratio,
    )
    generator.fill_jit_code()
    generator.fill_interpretation_loop()
    assert (
        len(generator.interpreter_instructions)
        == (generator.interpreter_call_size - 1)
        * (len(generator.jit_elements) - generator.pic_count)
        + generator.interpreter_call_size * generator.pic_count
        + Generator.INT_PROLOGUE_SIZE
        + Generator.INT_EPILOGUE_SIZE
    )

    # Monitor calls
    disasm = disasm_setup
    elt_addresses = [elt.address for elt in generator.jit_elements]
    mc_code = generator.generate_interpreter_machine_code()
    print(elt_addresses)
    for i, instr_list in enumerate(
        window(
            mc_code[Generator.INT_PROLOGUE_SIZE : -Generator.INT_EPILOGUE_SIZE],
            2,
        )
    ):
        current_address = (
            INTERPRETER_START_ADDRESS + (generator.interpreter_prologue_size + i) * 4
        )
        if [disasm.get_instruction_name(instr) for instr in instr_list] == [
            "auipc",
            "jalr",
        ]:
            pc_offset = disasm.extract_pc_relative_offset(instr_list)
            called_address = current_address + pc_offset
            assert called_address in elt_addresses
            elt_addresses.remove(called_address)
    # All elements have been called
    assert elt_addresses == []


# =================================
#         Generation tests
# =================================


@pytest.mark.parametrize(
    "jit_size, jit_nb_methods,pics_ratio",
    [
        (100, 10, 0),
        (200, 10, 0.2),
        (10000, 500, 0.5),
    ],
)
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
        pics_mean_case_nb=2,
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
        (50, 5, 0, 0.2, 0.1, 0.2, 0.01, 1),
        (200, 10, 0.2, 0.4, 0.2, 0.05, 0.2, 2),
        (10000, 500, 0.5, 0.5, 0.2, 0.1, 0.02, 3),
    ],
)
@pytest.mark.parametrize("generator_class", [Generator, TrampolineGenerator])
def test_execute_generated_binaries(
    jit_size,
    jit_nb_methods,
    meth_var_mean,
    pics_ratio,
    meth_var_stdev,
    call_occupation_mean,
    call_occupation_stdev,
    call_depth_mean,
    generator_class,
    cap_disasm_setup,
    handler_setup,
    uc_emul_full_setup,
):
    generator = generator_class(
        jit_start_address=JIT_START_ADDRESS,
        interpreter_start_address=INTERPRETER_START_ADDRESS,
        jit_size=jit_size,
        jit_nb_methods=jit_nb_methods,
        method_variation_mean=meth_var_mean,
        method_variation_stdev=meth_var_stdev,
        call_occupation_mean=call_occupation_mean,
        call_occupation_stdev=call_occupation_stdev,
        call_depth_mean=call_depth_mean,
        pics_mean_case_nb=1,
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
