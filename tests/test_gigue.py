from gigue.gigue import Gigue


# Test add jit code
def test_fill_jit_code():
    gigue = Gigue(
        jit_start_address=0x1000, interpreter_start_address=0xF000,
        method_nb=8, method_max_size=30, method_max_calls=5,
        pics_method_max_size=30, pics_max_cases=5, pics_ratio=0
    )
    gigue.fill_jit_code()


# Test add interpretation loop


# Test jit code generation


# Test interpretation loop generation


# Test bytes, disassembly and execution
