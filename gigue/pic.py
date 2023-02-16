import random
from typing import List

from gigue.builder import InstructionBuilder
from gigue.constants import CMP_REG
from gigue.constants import HIT_CASE_REG
from gigue.helpers import flatten_list
from gigue.helpers import gaussian_between
from gigue.instructions import Instruction
from gigue.method import Method


class PIC:
    def __init__(
        self,
        address: int,
        case_number: int,
        method_max_size: int,
        method_max_call_number: int,
        method_max_call_depth: int,
        hit_case_reg: int = HIT_CASE_REG,
        cmp_reg: int = CMP_REG,
    ):
        self.case_number: int = case_number
        self.address: int = address
        self.method_max_size: int = method_max_size
        self.method_max_call_number: int = method_max_call_number
        self.method_max_call_depth: int = method_max_call_depth
        # hit_case_reg: register in which the case_nb that should be ran is loaded
        # cmp_reg: register in which the running case nb is stored before comparison
        # Comparison and current registers
        self.cmp_reg: int = cmp_reg
        self.hit_case_reg: int = hit_case_reg

        self.builder: InstructionBuilder = InstructionBuilder()
        self.switch_instructions: List[Instruction] = []
        self.methods: List[Method] = []
        self.instructions: List[Instruction] = []
        self.machine_code: List[int] = []
        self.bytes: bytes = b""

    def get_callees(self):
        return list(set(flatten_list([method.callees for method in self.methods])))

    def get_switch_size(self):
        # switch corresponds to:
        # addi x6, x0, 1            (case 1)
        # bne  x5, x6, 8
        # jal  x0, method 1 offset
        # ...                       (case ...)
        # ret

        # The size is: instruction size * 3 (addi bne jalr) + 1 (ret)
        return 3 * self.case_number + 1

    def total_size(self):
        return self.get_switch_size() + sum(
            [method.total_size() for method in self.methods]
        )

    def accept_build_call(self, method_offset):
        hit_case = random.randint(1, self.case_number)
        # The -4 comes from the addi that has to be mitigated
        return self.builder.build_pic_call(method_offset - 4, hit_case)

    def add_case_methods(self, *args, **kwargs):
        method_address = self.address + self.get_switch_size() * 4
        for _ in range(self.case_number):
            body_size = gaussian_between(3, self.method_max_size)
            max_call_nb = min(
                self.method_max_call_number, Method.compute_max_call_number(body_size)
            )
            call_nb = abs(gaussian_between(-max_call_nb, max_call_nb))
            call_depth = abs(
                gaussian_between(
                    -self.method_max_call_depth, self.method_max_call_depth
                )
            )
            case_method = Method(
                address=method_address,
                body_size=body_size,
                call_number=call_nb,
                call_depth=call_depth,
            )
            case_method.fill_with_instructions(*args, **kwargs)
            self.methods.append(case_method)
            method_address += case_method.total_size() * 4

    def add_switch_instructions(self):
        # WARNING!!!! hit case starts at 1
        # The switch instructions consist of:
        #   1 - Loading the value to compare in cmp_reg (x6)
        #   2 - Compare to the current case that should be in hit_case_reg (x5)
        #   3 - Jump to the corresponding method if equal
        #   4 - Go to the next case if not
        #   5 - Repeat (1/2/3/4)
        #   6 - Simple ret at the end if no case was reached
        for case_nb, method in enumerate(self.methods):
            current_address = self.address + ((case_nb + 1) * 3) * 4
            method_offset = method.address - current_address
            switch_case = self.builder.build_switch_case(
                case_number=case_nb + 1,
                method_offset=method_offset,
                hit_case_reg=self.hit_case_reg,
                cmp_reg=self.cmp_reg,
            )
            self.switch_instructions.append(switch_case)
        self.switch_instructions.append([self.builder.build_ret()])

    def fill_with_instructions(self, registers, data_reg, data_size, weights):
        self.add_case_methods(
            registers=registers, data_reg=data_reg, data_size=data_size, weights=weights
        )
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
