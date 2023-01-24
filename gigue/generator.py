import random
from collections import defaultdict
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

from gigue.builder import InstructionBuilder
from gigue.constants import BIN_DIR
from gigue.constants import CALLER_SAVED_REG
from gigue.constants import INSTRUCTION_WEIGHTS
from gigue.helpers import flatten_list
from gigue.helpers import gaussian_between
from gigue.instructions import Instruction
from gigue.method import Method
from gigue.pic import PIC


class Generator:
    MAX_CODE_SIZE = 2 * 1024 * 1024  # 2mb
    INT_PROLOGUE_SIZE = 12  # 10 caller-saved stores + ra store + stack space
    INT_EPILOGUE_SIZE = 13  # 10 caller-saved loads + ra load + stack space + ret

    def __init__(
        self,
        jit_start_address: int,
        interpreter_start_address: int,
        jit_elements_nb: int,
        max_call_depth: int,
        max_call_nb: int,
        method_max_size: int,
        pics_method_max_size: int,
        pics_max_cases: int,
        pics_cmp_reg: int = 6,
        pics_hit_case_reg: int = 5,
        pics_ratio: float = 0.2,
        registers: Optional[List[int]] = None,
        output_jit_file: str = BIN_DIR + "jit.bin",
        output_interpret_file: str = BIN_DIR + "interpret.bin",
    ):
        # Registers
        if registers is None:
            self.registers: List[int] = CALLER_SAVED_REG
        # Memory index registers to use with loads/stores
        # TODO: self.mem_reg_index = ?
        # Addresses
        self.jit_start_address: int = jit_start_address
        self.interpreter_start_address: int = interpreter_start_address
        # Global parameters
        self.jit_elements_nb: int = jit_elements_nb  # Methods + PICs
        self.max_call_depth: int = max_call_depth
        self.max_call_nb: int = max_call_nb
        # Methods parameters
        self.method_max_size: int = method_max_size
        self.method_count: int = 0
        # PICs parameters
        self.pics_ratio: float = pics_ratio
        self.pics_max_cases: int = pics_max_cases
        self.pics_method_max_size: int = pics_method_max_size
        self.pics_hit_case_reg: int = pics_hit_case_reg
        self.pics_cmp_reg: int = pics_cmp_reg
        self.pic_count: int = 0
        # Generation
        self.builder: InstructionBuilder = InstructionBuilder()
        self.jit_elements: List[Union[Method, PIC]] = []
        self.jit_instructions: List[Instruction] = []
        self.call_depth_dict: Dict[int, List[Union[Method, PIC]]] = defaultdict(list)
        self.interpreter_instructions: List[Instruction] = []
        # MC/Bytes/Binary generation
        self.jit_machine_code: List[int] = []
        self.jit_bytes: List[bytes] = []
        self.interpreter_machine_code: List[int] = []
        self.interpreter_bytes: List[bytes] = []
        self.output_jit_bin: bytes = b""
        self.output_interpreter_bin: bytes = b""
        self.output_jit_file: str = output_jit_file
        self.output_interpreter_file: str = output_interpret_file

    #  JIT element generation
    # \______________________

    def add_method(self, address):
        body_size = gaussian_between(3, self.method_max_size)
        # To force the creation of leaf functions,
        # the gaussian distribution is centered
        # around 0 and the absolute value is used!
        max_call_nb = min(self.max_call_nb, body_size // 2 - 1)
        call_nb = abs(gaussian_between(-max_call_nb, max_call_nb))
        call_depth = (
            0
            if call_nb == 0
            else abs(gaussian_between(-self.max_call_depth, self.max_call_depth))
        )
        method = Method(
            address=address,
            body_size=body_size,
            call_number=call_nb,
            call_depth=call_depth,
            registers=CALLER_SAVED_REG,
        )
        self.jit_elements.append(method)
        self.call_depth_dict[call_depth].append(method)
        self.method_count += 1
        return method

    def add_leaf_method(self, address):
        body_size = gaussian_between(3, self.method_max_size)
        method = Method(
            address=address,
            body_size=body_size,
            call_number=0,
            call_depth=0,
            registers=CALLER_SAVED_REG,
        )
        self.jit_elements.append(method)
        self.call_depth_dict[0].append(method)
        self.method_count += 1
        return method

    def add_pic(self, address):
        cases_nb = random.randint(2, self.pics_max_cases)
        pic = PIC(
            address=address,
            case_number=cases_nb,
            method_max_size=self.pics_method_max_size,
            method_max_call_number=self.max_call_nb,
            method_max_call_depth=self.max_call_depth,
            hit_case_reg=self.pics_hit_case_reg,
            cmp_reg=self.pics_cmp_reg,
            registers=CALLER_SAVED_REG,
        )
        self.jit_elements.append(pic)
        for method in pic.methods:
            self.call_depth_dict[method.call_depth].append(method)
        self.pic_count += 1
        return pic

    #  Interpretation loop calling construction
    # \________________________________________

    # TODO: Switch the logic in the builder?
    def build_element_call(self, element, offset):
        return element.accept_build(self, offset)

    def build_method_call(self, method, offset):
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

    #  JIT filling and patching
    # \________________________

    def fill_jit_code(self, weights=None):
        if weights is None:
            weights = INSTRUCTION_WEIGHTS
        current_address = self.jit_start_address
        current_element_count = 0
        # Add a first leaf method
        leaf_method = self.add_leaf_method(current_address)
        leaf_method.fill_with_instructions(weights)
        current_address += leaf_method.total_size() * 4
        current_element_count += 1
        # Add other methods
        while current_element_count < self.jit_elements_nb:
            code_type = random.choices(
                ["method", "pic"], [1 - self.pics_ratio, self.pics_ratio]
            )[0]
            adder_function = getattr(Generator, "add_" + code_type)
            current_element = adder_function(self, current_address)
            current_element.fill_with_instructions(weights)
            current_address += current_element.total_size() * 4
            current_element_count += 1

    def extract_callees(self, call_depth, nb):
        possible_callees = flatten_list(
            [
                self.call_depth_dict[i]
                for i in self.call_depth_dict.keys()
                if i < call_depth
            ]
        )
        return random.choices(possible_callees, k=nb)

    def patch_jit_calls(self):
        for elt in self.jit_elements:
            if isinstance(elt, PIC):
                for method in elt.methods:
                    if method.call_depth == 0:
                        continue
                    method.patch_calls(
                        self.extract_callees(method.call_depth, method.call_number)
                    )
            elif isinstance(elt, Method):
                if elt.call_depth == 0:
                    continue
                elt.patch_calls(self.extract_callees(elt.call_depth, elt.call_number))

    #  Interpretation loop filling
    # \___________________________

    def fill_interpretation_loop(self):
        prologue_instructions = self.builder.build_prologue(10, 0, True)
        self.interpreter_instructions += prologue_instructions
        current_address = (
            self.interpreter_start_address + len(prologue_instructions) * 4
        )
        # for all addresses in methods and pics, generate a call
        shuffled_elements = self.jit_elements.copy()
        random.shuffle(shuffled_elements)
        for element in shuffled_elements:
            call_size = self.build_element_call(
                element, element.address - current_address
            )
            current_address += call_size
        epilogue_instructions = self.builder.build_epilogue(10, 0, True)
        self.interpreter_instructions += epilogue_instructions

    #  Machine code generation
    # \_______________________

    def generate_jit_machine_code(self):
        self.jit_machine_code = [elt.generate() for elt in self.jit_elements]
        return self.jit_machine_code

    def generate_interpreter_machine_code(self):
        self.interpreter_machine_code += [
            instr.generate() for instr in self.interpreter_instructions
        ]
        return self.interpreter_machine_code

    #  Bytes generation
    # \________________

    def generate_jit_bytes(self):
        self.jit_bytes = [elt.generate_bytes() for elt in self.jit_elements]
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
        self.patch_jit_calls()
        self.fill_interpretation_loop()
        # Generate the machine code
        self.generate_jit_machine_code()
        self.generate_interpreter_machine_code()
        # Generate bytes
        self.generate_interpreter_bytes()
        # Generate binaries
        self.generate_jit_binary()
        self.generate_interpreter_binary()
        # Write binaries
        self.write_binaries()
