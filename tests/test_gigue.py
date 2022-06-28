import pytest

from gigue.gigue import Gigue
from gigue.disassembler import Disassembler

# =================================
#            Constants
# =================================

disassembler = Disassembler()


# =================================
#          Filling tests
# =================================


@pytest.mark.parametrize("jit_elements_nb", [8, 10, 20, 30, 50, 100])
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
def test_fill_jit_code(jit_elements_nb, method_max_size):
    gigue = Gigue(
        jit_start_address=0x1000, interpreter_start_address=0xF000,
        jit_elements_nb=jit_elements_nb, method_max_size=method_max_size, method_max_calls=5,
        pics_method_max_size=30, pics_max_cases=5, pics_ratio=0
    )
    gigue.fill_jit_code()
    assert len(gigue.jit_methods) == jit_elements_nb


@pytest.mark.parametrize("jit_elements_nb", [8, 10, 20, 30, 50, 100])
@pytest.mark.parametrize("method_max_size", [20, 50, 100, 200])
def test_fill_interpretation_loop(jit_elements_nb, method_max_size):
    gigue = Gigue(
        jit_start_address=0x1000, interpreter_start_address=0xF000,
        jit_elements_nb=jit_elements_nb, method_max_size=method_max_size, method_max_calls=5,
        pics_method_max_size=30, pics_max_cases=5, pics_ratio=0
    )
    gigue.fill_jit_code()
    gigue.fill_interpretation_loop()
    assert len(gigue.interpreter_calls) == jit_elements_nb
    for i, (jit_element, call_instruction) in enumerate(zip(gigue.jit_elements, gigue.interpreter_calls)):
        print("{}: {} | {}".format(i, jit_element, call_instruction))
        assert call_instruction[0].name == "auipc"
        assert call_instruction[1].name == "jalr"
        print("higho: {}, lowo: {}".format(hex(call_instruction[0].imm), hex(call_instruction[1].imm)))
        instructions = [call_instruction[0].generate(), call_instruction[1].generate()]
        call_offset = disassembler.extract_call_offset(instructions)
        assert (gigue.interpreter_start_address + i * 8) + call_offset == jit_element.address


# Test jit code generation


# Test interpretation loop generation


# Test bytes, disassembly and execution
