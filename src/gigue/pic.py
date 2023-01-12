import random

from gigue.builder import InstructionBuilder
from gigue.constants import CALLER_SAVED_REG
from gigue.constants import INSTRUCTION_WEIGHTS
from gigue.method import Method


class PIC:
    def __init__(
        self,
        address,
        case_number,
        method_max_size,
        method_max_calls,
        hit_case_reg,
        cmp_reg,
        registers,
    ):
        # TODO: Store case method call depth
        # hit_case_reg: register in which the case_nb that should be ran is loaded
        # cmp_reg: register in which the running case nb is stored before comparison
        self.case_number = case_number
        self.address = address
        self.registers = registers
        self.method_max_size = method_max_size
        self.method_max_calls = method_max_calls
        self.hit_case_reg = hit_case_reg
        self.cmp_reg = cmp_reg

        self.builder = InstructionBuilder()
        self.switch_instructions = []
        self.methods = []
        self.instructions = []
        self.machine_code = []
        self.bytes = b""

    def get_switch_size(self):
        # switch corresponds to:
        # addi x6, x0, 1            (case 1)
        # bne  x5, x6, 8
        # jal  x0, method 1 offset
        # ...                       (case ...)
        # ret

        # The size is: instruction size * 3 (addi bne jalr) + 1 (ret)
        return 4 * (3 * self.case_number + 1)

    def total_size(self):
        return self.get_switch_size() + sum(
            [method.total_size() for method in self.methods]
        )

    def add_case_methods(self, weights=None):
        if weights is None:
            weights = INSTRUCTION_WEIGHTS
        method_address = self.address + self.get_switch_size()
        for _ in range(self.case_number):
            size = random.randint(3, self.method_max_size)
            call_nb = random.randint(0, min(self.method_max_calls, size // 2 - 1))
            case_method = Method(
                address=method_address,
                body_size=size,
                call_number=call_nb,
                registers=CALLER_SAVED_REG,
            )
            case_method.fill_with_instructions(weights)
            self.methods.append(case_method)
            # print(hex(case_method.address))
            method_address += case_method.total_size() * 4

    def add_switch_instructions(self):
        # The switch instructions consist of:
        #   1 - Loading the value to compare in cmp_reg (x6)
        #   2 - Compare to the current case that should be in hit_case_reg (x5)
        #   3 - Jump to the corresponding method if equal
        #   4 - Go to the next case if not
        #   5 - Repeat (1/2/3/4)
        #   6 - Simple ret at the end if no case was reached
        for case_nb, method in enumerate(self.methods):
            # method_offset = method.address - self.address + (case_nb * 3 - 1) * 4
            current_address = self.address + (case_nb * 3) * 4
            method_offset = method.address - current_address
            # print(method_offset)
            switch_case = self.builder.build_switch_case(
                case_number=case_nb + 1,
                method_offset=method_offset,
                hit_case_reg=self.hit_case_reg,
                cmp_reg=self.cmp_reg,
            )
            self.switch_instructions.append(switch_case)
        self.switch_instructions.append([self.builder.build_ret()])

    def fill_with_instructions(self, weights=None):
        self.add_case_methods(weights)
        self.add_switch_instructions()

    def generate(self):
        for case in self.switch_instructions:
            self.machine_code += [instr.generate() for instr in case]
        self.machine_code += [method.generate() for method in self.methods]
        return self.machine_code

    def generate_bytes(self):
        for case in self.switch_instructions:
            self.bytes += b"".join([instr.generate_bytes() for instr in case])
        self.bytes += b"".join([method.generate_bytes() for method in self.methods])
        return self.bytes

    def accept_build(self, generator, method_offset):
        return generator.build_pic_call(self, method_offset)
