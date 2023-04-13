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
    "jit_elements_nb, method_max_size, pics_ratio",
    [
        (5, 5, 0),
        (20, 20, 0.2),
        (100, 50, 0.5),
    ],
)
def test_execute_trampoline_generated_binaries(
    jit_elements_nb,
    method_max_size,
    pics_ratio,
    cap_disasm_custom_setup,
    fixer_handler_setup,
    uc_emul_full_setup,
):
    generator = FIXERTrampolineGenerator(
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

    uc_emul.emu_start(INTERPRETER_START_ADDRESS, RET_ADDRESS)
    uc_emul.emu_stop()
