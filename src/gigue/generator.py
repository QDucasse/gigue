import random

from gigue.builder import InstructionBuilder
from gigue.constants import BIN_DIR
from gigue.constants import CALLER_SAVED_REG
from gigue.constants import INSTRUCTION_WEIGHTS
from gigue.method import Method
from gigue.pic import PIC


class Generator:
    MAX_CODE_SIZE = 2 * 1024 * 1024  # 2mb
    INT_PROLOGUE_SIZE = 12  # 10 caller-saved stores + ra store + stack space
    INT_EPILOGUE_SIZE = 13  # 10 caller-saved loads + ra load + stack space + ret

    def __init__(
        self,
        jit_start_address,
        interpreter_start_address,
        jit_elements_nb,
        method_max_size,
        method_max_calls,
        pics_method_max_size,
        pics_max_cases,
        pics_methods_max_calls,
        pics_cmp_reg=6,
        pics_hit_case_reg=5,
        pics_ratio=0.2,
        registers=None,
        output_jit_file=BIN_DIR + "jit.bin",
        output_interpret_file=BIN_DIR + "interpret.bin",
    ):
        if registers is None:
            self.registers = CALLER_SAVED_REG
        self.jit_start_address = jit_start_address
        self.interpreter_start_address = interpreter_start_address
        self.jit_elements_nb = jit_elements_nb  # Methods + PICs
        # Methods parameters
        self.method_max_size = method_max_size
        self.method_max_calls = method_max_calls
        self.method_count = 0
        # PICs parameters
        self.pics_ratio = pics_ratio
        self.pics_max_cases = pics_max_cases
        self.pics_method_max_size = pics_method_max_size
        self.pics_methods_max_calls = pics_methods_max_calls
        self.pics_hit_case_reg = pics_hit_case_reg
        self.pics_cmp_reg = pics_cmp_reg
        self.pic_count = 0
        # Generation
        self.builder = InstructionBuilder()
        self.jit_methods = []
        self.jit_pics = []
        self.jit_elements = []  # Shuffled concatenation of above
        self.jit_instructions = []
        self.interpreter_instructions = []
        # MC/Bytes/Binary generation
        self.jit_machine_code = []
        self.jit_bytes = []
        self.interpreter_machine_code = []
        self.interpreter_bytes = []
        self.output_jit_bin = b""
        self.output_interpreter_bin = b""
        self.output_jit_file = output_jit_file
        self.output_interpreter_file = output_interpret_file

    def add_method(self, address):
        body_size = random.randint(3, self.method_max_size)
        print(f"Method body size: {body_size}")
        call_nb = 1  # random.randint(0, min(self.method_max_calls, size // 2 - 1))
        method = Method(
            address=address,
            body_size=body_size,
            call_number=call_nb,
            registers=CALLER_SAVED_REG,
        )
        self.jit_methods.append(method)
        self.method_count += 1
        return method

    def add_pic(self, address):
        cases_nb = random.randint(2, self.pics_max_cases)
        pic = PIC(
            address=address,
            case_number=cases_nb,
            method_max_size=self.pics_method_max_size,
            method_max_calls=self.pics_methods_max_calls,
            hit_case_reg=self.pics_hit_case_reg,
            cmp_reg=self.pics_cmp_reg,
            registers=CALLER_SAVED_REG,
        )
        self.jit_pics.append(pic)
        self.pic_count += 1
        return pic

    def build_element_call(self, element, offset):
        return element.accept_build(self, offset)

    def build_method_call(self, method, offset):
        print(f"Call offset: {hex(offset)}")
        call_instructions = self.builder.build_method_call(offset)
        self.interpreter_instructions += call_instructions
        return len(call_instructions) * 4

    def build_pic_call(self, pic, offset):
        hit_case = random.randint(1, pic.case_number)
        call_instructions = self.builder.build_pic_call(
            offset, hit_case, pic.hit_case_reg
        )
        self.interpreter_instructions += call_instructions
        return len(call_instructions) * 4

    def fill_jit_code(self, weights=None):
        if weights is None:
            weights = INSTRUCTION_WEIGHTS
        current_address = self.jit_start_address
        current_element_count = 0
        while current_element_count < self.jit_elements_nb:
            code_type = random.choices(
                ["method", "pic"], [1 - self.pics_ratio, self.pics_ratio]
            )[0]
            # print("_____________________________________________")
            adder_function = getattr(Generator, "add_" + code_type)
            current_element = adder_function(self, current_address)
            current_element.fill_with_instructions(weights)
            # print(f"Method total size: {current_element.total_size()}")
            # print(f"Previous address: {hex(current_address)}")
            # current_address += current_element.total_size()
            current_address += current_element.total_size() * 4
            # print(f"Elements: {[ins.__class__.__name__ for ins in current_element.instructions]}")
            # print(f"Element size: {current_element.total_size() * 4}, {hex(current_element.total_size() * 4)}")
            # print(f"Element nb of instructions: {len(current_element.instructions)}")
            # print(f"New address: {hex(current_address)}")
            self.jit_instructions += current_element.instructions
            current_element_count += 1

    def patch_jit_calls(self):
        # Patch methods
        # TODO:
        # [ ] 1. Change the call building in methods
        # [ ]   1.1 Add a frame creation -> save ra
        # [ ]   1.1 Add a frame creation -> restore ra
        # [ ] 2. Change the order of instruction generation
        # [ ]   2.1 First generate random instructions (no jumps or branches)
        # [ ]   2.2 Generate patched calls
        # [ ]   2.3 Add jumps and branches and avoid calls
        for method in self.jit_methods:
            callees = random.sample(self.jit_methods, k=method.call_number)
            # Remove recursivity
            if method in callees:
                callees.remove(method)
            method.patch_calls(callees)
        # Patch pics methods

    def fill_interpretation_loop(self):
        prologue_instructions = self.builder.build_prologue(10, 0, True)
        self.interpreter_instructions += prologue_instructions
        current_address = (
            self.interpreter_start_address + len(prologue_instructions) * 4
        )
        # for all addresses in methods and pics, generate a call
        self.jit_elements = self.jit_methods + self.jit_pics
        print([hex(elt.address) for elt in self.jit_elements])
        random.shuffle(self.jit_elements)
        print([hex(elt.address) for elt in self.jit_elements])
        for element in self.jit_elements:
            call_size = self.build_element_call(
                element, element.address - current_address
            )
            current_address += call_size
        epilogue_instructions = self.builder.build_epilogue(10, 0, True)
        self.interpreter_instructions += epilogue_instructions

    #  Machine code generation
    # \_______________________

    def generate_jit_machine_code(self):
        self.jit_machine_code = [
            instr.generate() for instr in self.jit_instructions
        ]  # [elt.generate() for elt in self.jit_elements]
        return self.jit_machine_code

    def generate_interpreter_machine_code(self):
        self.interpreter_machine_code += [
            instr.generate() for instr in self.interpreter_instructions
        ]
        return self.interpreter_machine_code

    #  Bytes generation
    # \________________

    def generate_jit_bytes(self):
        self.jit_bytes = [instr.generate_bytes() for instr in self.jit_instructions]
        return self.jit_bytes

    def generate_interpreter_bytes(self):
        self.interpreter_bytes = [
            instr.generate_bytes() for instr in self.interpreter_instructions
        ]
        return self.interpreter_bytes

    def generate_jit_binary(self):
        self.output_jit_bin = b"".join(self.jit_bytes)
        return self.output_jit_bin

    def generate_interpreter_binary(self):
        self.output_interpreter_bin = b"".join(self.interpreter_bytes)
        return self.output_interpreter_bin

    #  Binary Writing
    # \______________

    def write_binaries(self):
        jit_bin = open(self.output_jit_file, "wb")
        jit_bin.write(self.output_jit_bin)
        jit_bin.close()
        interpreter_bin = open(self.output_interpreter_file, "wb")
        interpreter_bin.write(self.output_interpreter_bin)
        interpreter_bin.close()

    #  Wrap-up
    # \_______

    def main(self):
        # Fill
        self.fill_jit_code()
        # self.patch_jit_calls()
        self.fill_interpretation_loop()
        # Generate the machine code
        self.generate_jit_machine_code()
        self.generate_interpreter_machine_code()
        # Generate bytes
        self.generate_jit_bytes()
        self.generate_interpreter_bytes()
        # Generate binaries
        self.generate_jit_binary()
        self.generate_interpreter_binary()
        # Write binaries
        self.write_binaries()
