import random

from gigue.builder import InstructionBuilder
from gigue.constants import CALLER_SAVED_REG
from gigue.constants import INSTRUCTION_WEIGHTS
from gigue.method import PIC
from gigue.method import Method


class Gigue:
    MAX_CODE_SIZE = 2 * 1024 * 1024  # 2mb
    BIN_DIR = "bin/"

    def __init__(self, jit_start_address, interpreter_start_address,
                 jit_elements_nb, method_max_size, method_max_calls,
                 pics_method_max_size, pics_max_cases, pics_ratio=0.2,
                 registers=None,
                 output_jit_file=BIN_DIR+"jit.out",
                 output_interpret_file=BIN_DIR+"interpret.out",):
        if registers is None:
            self.registers = CALLER_SAVED_REG
        self.jit_start_address = jit_start_address
        self.interpreter_start_address = interpreter_start_address
        # Methods parameters
        self.jit_elements_nb = jit_elements_nb  # Methods + PICs
        self.method_max_size = method_max_size
        self.method_max_calls = method_max_calls
        # PICs parameters
        self.pics_ratio = pics_ratio
        self.pics_max_cases = pics_max_cases
        self.pics_method_max_size = pics_method_max_size
        # Generation
        self.builder = InstructionBuilder()  # for the interpretation loop
        self.jit_methods = []
        self.jit_pics = []
        self.jit_elements = []  # Shuffled concatenation of above
        self.jit_machine_code = []
        self.jit_bytes = []
        self.interpreter_calls = []
        self.interpreter_machine_code = []
        self.interpreter_bytes = []
        self.output_jit_bin = b''
        self.output_interpreter_bin = b''
        self.output_jit_file = output_jit_file
        self.output_interpreter_file = output_interpret_file

    @staticmethod
    def flatten_list(nested_list):
        return [item for sublist in nested_list for item in sublist]

    def add_method(self, address):
        size = random.randint(3, self.method_max_size)
        call_nb = random.randint(0, min(self.method_max_calls, size // 2 - 1))
        method = Method(size, call_nb, address, CALLER_SAVED_REG)
        self.jit_methods.append(method)
        return method

    def add_pic(self, address):
        method_size = random.randint(1, self.pics_method_max_size)
        cases_nb = random.randint(2, self.pics_max_cases)
        pic = PIC(cases_nb, method_size, address, CALLER_SAVED_REG)
        self.jit_pics.append(pic)
        return pic

    def fill_jit_code(self, weights=None):
        if weights is None:
            weights = INSTRUCTION_WEIGHTS
        current_address = self.jit_start_address
        current_element_count = 0
        while current_element_count < self.jit_elements_nb:
            code_type = random.choices(["method", "pic"], [1 - self.pics_ratio, self.pics_ratio])[0]
            adder_function = getattr(Gigue, "add_" + code_type)
            current_element = adder_function(self, current_address)
            current_element.add_instructions(weights)
            current_address += len(current_element.generate()) * 4
            current_element_count += 1

    def fill_interpretation_loop(self):
        current_address = self.interpreter_start_address
        # for all addresses in methods and pics, generate a call
        self.jit_elements = self.jit_methods + self.jit_pics
        random.shuffle(self.jit_elements)
        for element in self.jit_elements:
            # generate a call
            call_instructions = self.builder.build_call(element.address - current_address)
            self.interpreter_calls.append(call_instructions)
            current_address += 8

    def generate_jit_machine_code(self):
        self.jit_machine_code = [elt.generate() for elt in self.jit_elements]
        return self.jit_machine_code

    def generate_interpreter_machine_code(self):
        for call in self.interpreter_calls:
            self.interpreter_machine_code.append([instr.generate() for instr in call])
        return self.interpreter_machine_code

    def generate_jit_bytes(self):
        self.jit_bytes = [elt.generate_bytes() for elt in self.jit_elements]
        return self.jit_bytes

    def generate_interpreter_bytes(self):
        for call in self.interpreter_calls:
            self.interpreter_bytes.append([instr.generate_bytes() for instr in call])
        return self.interpreter_bytes

    def generate_jit_binary(self):
        self.output_jit_bin = b''.join(self.jit_bytes)
        return self.output_jit_bin

    def generate_interpreter_binary(self):
        self.output_interpreter_bin = b''.join(self.interpreter_bytes)
        return self.output_interpreter_bin

    def write_binaries(self):
        jit_bin = open(self.output_jit_file, "wb")
        jit_bin.write(self.output_jit_bin)
        jit_bin.close()
        interpreter_bin = open(self.output_interpreter_file, "wb")
        interpreter_bin.write(self.output_interpreter_bin)
        interpreter_bin.close()

    def generate_gigue(self):
        # Fill
        self.fill_jit_code()
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
