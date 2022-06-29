import random

from gigue.builder import InstructionBuilder
from gigue.constants import CALLER_SAVED_REG
from gigue.constants import INSTRUCTION_WEIGHTS
from gigue.method import Method


class PIC:
    def __init__(self, address, case_number, method_max_size, method_max_calls, temp_reg, registers):
        self.case_number = case_number
        self.address = address
        self.registers = registers
        self.method_max_size = method_max_size
        self.method_max_calls = method_max_calls
        self.temp_reg = temp_reg

        self.builder = InstructionBuilder()
        self.switch_instructions = []
        self.methods = []
        self.machine_code = []
        self.bytes = b''

    def get_switch_size(self):
        # switch corresponds to:
        # addi x6, x0, 1            (case 1)
        # bne  x5, x6, 8
        # jal  x0, method 1 offset
        # ...                       (case ...)
        # ret

        # The size is: instruction size * 3 (addi bne jalr) + 1 (ret)
        return 4 * 3 * self.case_number + 1

    def add_case_methods(self, weights=None):
        if weights is None:
            weights = INSTRUCTION_WEIGHTS
        for _ in range(self.case_number):
            method_address = self.address + self.get_switch_size()
            size = random.randint(3, self.method_max_size)
            call_nb = random.randint(0, min(self.method_max_calls, size // 2 - 1))
            case_method = Method(size, call_nb, method_address, CALLER_SAVED_REG)
            case_method.add_instructions(weights)
            self.methods.append(case_method)
            method_address += case_method.size * 4

    def add_switch_instructions(self):
        # The switch instructions consist of:
        #   1 - Loading the value to compare in x6
        #   2 - Compare to the current case (should be in x5)
        #   3 - Jump to the corresponding method if equal
        #   4 - Go to the next case if not
        #   5 - Repeat (1/2/3/4)
        #   6 - Simple ret at the end if no case was reached
        for case_nb, method in enumerate(self.methods):
            method_offset = method.address - self.address + (case_nb * 3 - 1) * 4
            switch_case = self.builder.build_switch_case(case_nb + 1, method_offset, self.temp_reg)
            self.switch_instructions.append(switch_case)
        self.switch_instructions.append([self.builder.build_ret()])

    def add_instructions(self, weights=None):
        self.add_case_methods(weights)
        self.add_switch_instructions()

    def generate(self):
        for case in self.switch_instructions:
            self.machine_code.append([instr.generate() for instr in case])
        self.machine_code.extend([method.generate() for method in self.methods])
        return self.machine_code

    def generate_bytes(self):
        # TODO: List comprehension maybe?
        for case in self.switch_instructions:
            for instruction in case:
                self.bytes += instruction.generate_bytes()
        for method in self.methods:
            self.bytes += method.generate_bytes()
        return self.bytes
