import logging

import pytest

from gigue.rimi.rimi_generator import (
    RIMIFullTrampolineGenerator,
    RIMIShadowStackTrampolineGenerator,
)
from tests.conftest import (
    INTERPRETER_START_ADDRESS,
    JIT_START_ADDRESS,
    RET_ADDRESS,
    TEST_DATA_REG,
    TEST_DATA_SIZE,
    cap_disasm_bytes,
    check_size,
)
from tests.rimi.conftest import TEST_RIMI_SSP_REG, start_resumable_emulation

logger = logging.getLogger(__name__)


@pytest.mark.parametrize(
    "jit_elements_nb, method_max_size, pics_ratio",
    [
        (5, 5, 0),
        (20, 20, 0.2),
        (100, 50, 0.5),
    ],
)
def test_execute_shadow_stack_trampoline_generated_binaries(
    jit_elements_nb,
    method_max_size,
    pics_ratio,
    cap_disasm_custom_setup,
    rimi_handler_setup,
    rimi_uc_emul_full_setup,
):
    generator = RIMIShadowStackTrampolineGenerator(
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
        rimi_ssp_reg=TEST_RIMI_SSP_REG,
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
    uc_emul = rimi_uc_emul_full_setup
    uc_emul.mem_write(INTERPRETER_START_ADDRESS, interpreter_binary)
    uc_emul.mem_write(JIT_START_ADDRESS, jit_binary)

    # Handler
    rimi_handler = rimi_handler_setup
    rimi_handler.hook_instr_tracer(uc_emul)
    rimi_handler.hook_handler(uc_emul)

    start_address = INTERPRETER_START_ADDRESS
    end_address = RET_ADDRESS

    start_resumable_emulation(uc_emul, start_address, end_address)


@pytest.mark.parametrize(
    "jit_elements_nb, method_max_size, pics_ratio",
    [
        (5, 5, 0),
        (20, 20, 0.2),
        (100, 50, 0.5),
    ],
)
def test_execute_full_trampoline_generated_binaries(
    jit_elements_nb,
    method_max_size,
    pics_ratio,
    cap_disasm_custom_setup,
    rimi_handler_setup,
    rimi_uc_emul_full_setup,
):
    generator = RIMIFullTrampolineGenerator(
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
        rimi_ssp_reg=TEST_RIMI_SSP_REG,
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
    uc_emul = rimi_uc_emul_full_setup
    uc_emul.mem_write(INTERPRETER_START_ADDRESS, interpreter_binary)
    uc_emul.mem_write(JIT_START_ADDRESS, jit_binary)

    # Handler
    rimi_handler = rimi_handler_setup
    rimi_handler.hook_instr_tracer(uc_emul)
    rimi_handler.hook_handler(uc_emul)

    start_address = INTERPRETER_START_ADDRESS
    end_address = RET_ADDRESS

    start_resumable_emulation(uc_emul, start_address, end_address)
