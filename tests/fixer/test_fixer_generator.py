import pytest

from gigue.fixer.fixer_generator import FIXERTrampolineGenerator
from tests.conftest import (
    INTERPRETER_START_ADDRESS,
    JIT_START_ADDRESS,
    RET_ADDRESS,
    TEST_DATA_REG,
    TEST_DATA_SIZE,
    cap_disasm_bytes,
    check_size,
)
from tests.fixer.conftest import TEST_FIXER_CMP_REG


@pytest.mark.parametrize(
    (
        "jit_size, jit_nb_methods, pics_ratio, meth_var_mean, meth_var_stdev,"
        " call_occupation_mean, call_occupation_stdev, call_depth_mean"
    ),
    [
        (50, 5, 0, 0.2, 0.1, 0.2, 0.1, 1),
        (200, 10, 0.2, 0.4, 0.2, 0.4, 0.2, 2),
        (10000, 500, 0.5, 0.5, 0.2, 0.5, 0.2, 3),
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
    cap_disasm_custom_setup,
    fixer_handler_setup,
    uc_emul_full_setup,
):
    generator = FIXERTrampolineGenerator(
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
        fixer_cmp_reg=TEST_FIXER_CMP_REG,
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
    cap_disasm = cap_disasm_custom_setup

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
    fixer_handler = fixer_handler_setup
    fixer_handler.shadow_stack.append(RET_ADDRESS)
    fixer_handler.hook_instr_tracer(uc_emul)
    fixer_handler.hook_handler(uc_emul)

    # TODO: Something fishy!
    # uc_emul.emu_start(INTERPRETER_START_ADDRESS, RET_ADDRESS)
    # uc_emul.emu_stop()
