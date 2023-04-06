import pytest

from gigue.fixer.fixer_generator import FIXERTrampolineGenerator
from tests.conftest import (
    INTERPRETER_START_ADDRESS,
    JIT_START_ADDRESS,
    RET_ADDRESS,
    TEST_DATA_REG,
    TEST_DATA_SIZE,
    bin_info,
    cap_disasm_bytes,
)


@pytest.mark.parametrize(
    "jit_elements_nb", [5, 20, 200],
)
@pytest.mark.parametrize(
    "method_max_size",
    [5, 20, 50],
)
@pytest.mark.parametrize(
    "pics_ratio",
    [0, 0.2, 0.5],
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
    )
    generator.fill_jit_code()
    generator.patch_jit_calls()
    generator.fill_interpretation_loop()
    generator.generate_jit_machine_code()
    generator.generate_interpreter_machine_code()
    generator.generate_jit_bytes()
    generator.generate_interpreter_bytes()

    # Capstone disasm:
    cap_disasm = cap_disasm_custom_setup

    # Interpreter bin
    interpreter_binary = generator.generate_interpreter_binary()
    bin_info(interpreter_binary, INTERPRETER_START_ADDRESS)
    cap_disasm_bytes(cap_disasm, interpreter_binary, INTERPRETER_START_ADDRESS)
    # JIT bin
    jit_binary = generator.generate_jit_binary()
    bin_info(jit_binary, JIT_START_ADDRESS)
    cap_disasm_bytes(cap_disasm, jit_binary, JIT_START_ADDRESS)

    # Emulation/track/7ee1a4iou7gFi5REoufuxV
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(INTERPRETER_START_ADDRESS, interpreter_binary)
    uc_emul.mem_write(JIT_START_ADDRESS, jit_binary)

    # Handler
    fixer_handler = fixer_handler_setup
    fixer_handler.shadow_stack.append(RET_ADDRESS)
    # handler.hook_exception_tracer(uc_emul)
    fixer_handler.hook_instr_tracer(uc_emul)
    fixer_handler.hook_handler(uc_emul)

    uc_emul.emu_start(INTERPRETER_START_ADDRESS, RET_ADDRESS)
    uc_emul.emu_stop()
