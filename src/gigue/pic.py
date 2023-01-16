from typing import List
from typing import Optional

from gigue.builder import InstructionBuilder
from gigue.constants import CALLER_SAVED_REG
from gigue.constants import CMP_REG
from gigue.constants import HIT_CASE_REG
from gigue.constants import INSTRUCTION_WEIGHTS
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
        registers: List[int],
        hit_case_reg: Optional[int] = None,
        cmp_reg: Optional[int] = None,
    ):
        self.case_number: int = case_number
        self.address: int = address
        self.registers: List[int] = registers
        self.method_max_size: int = method_max_size
        self.method_max_call_number: int = method_max_call_number
        self.method_max_call_depth: int = method_max_call_depth
        # hit_case_reg: register in which the case_nb that should be ran is loaded
        # cmp_reg: register in which the running case nb is stored before comparison
        # Comparison and current registers
        if cmp_reg is None:
            cmp_reg = CMP_REG
        self.cmp_reg: int = cmp_reg
        if hit_case_reg is None:
            hit_case_reg = HIT_CASE_REG
        self.hit_case_reg: int = hit_case_reg

        self.builder: InstructionBuilder = InstructionBuilder()
        self.switch_instructions: List[Instruction] = []
        self.methods: List[Method] = []
        self.instructions: List[Instruction] = []
        self.machine_code: List[int] = []
        self.bytes: bytes = b""

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

    def add_case_methods(self, weights=None):
        if weights is None:
            weights = INSTRUCTION_WEIGHTS
        method_address = self.address + self.get_switch_size() * 4
        for _ in range(self.case_number):
            body_size = gaussian_between(3, self.method_max_size)
            max_call_nb = min(self.method_max_call_number, body_size // 2 - 1)
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
                registers=CALLER_SAVED_REG,
            )
            case_method.fill_with_instructions(weights)
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
