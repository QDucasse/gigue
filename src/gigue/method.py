import random
from typing import List

from gigue.builder import InstructionBuilder
from gigue.constants import INSTRUCTION_WEIGHTS
from gigue.instructions import Instruction


def raise_call_number_value_error(call_number, size):
    max_call_number = (size - 1) // 2
    raise ValueError(
        "ValueError: Call number should be <= {} and is {}.".format(
            max_call_number, call_number
        )
        + "\n  Number of calls in a method cannot be greater than (size - 1) // 2 "
        + "\n  (note: '-1' for ret and '//2' because a call is composed of two instructions)."
    )


def raise_call_patch_recursive_error(method, callees):
    raise ValueError(
        "ValueError: infinite call loop as {} is in {}".format(method, callees)
    )


class Method:
    def __init__(
        self,
        address: int,
        body_size: int,
        call_number: int,
        registers: List[int],
        call_depth: int = 1,
        used_s_regs: int = 1,
        local_vars_nb: int = 2,
    ):
        self.address: int = address
        self.body_size: int = body_size
        self.call_depth: int = call_depth
        self.used_s_regs: int = used_s_regs
        self.local_vars_nb: int = local_vars_nb

        # The calls will be added once random instructions are generated to
        # fill the method body. As a call takes two instructions and the method
        # should end with a ret, the max number of calls is (body_size -1) // 2 for
        # a given method body size.

        if call_number > (body_size - 1) // 2:
            raise_call_number_value_error(call_number, body_size)
        self.call_number: int = call_number

        self.is_leaf: bool = self.call_number == 0
        self.prologue_size: int = 0
        self.epilogue_size: int = 0

        self.registers: List[int] = registers

        self.builder: InstructionBuilder = InstructionBuilder()
        self.instructions: List[Instruction] = []
        self.callees: List[Method] = []
        self.machine_code: List[int] = []
        self.bytes: bytes = b""

    def total_size(self):
        if self.prologue_size == 0 or self.epilogue_size == 0:
            raise ValueError
        return self.body_size + self.prologue_size + self.epilogue_size

    def fill_with_nops(self):
        for _ in range(self.body_size):
            self.instructions.append(self.builder.build_nop())

    def fill_with_instructions(self, weights=None):
        # Weights = [R, I, U, J, B]
        if weights is None:
            weights = INSTRUCTION_WEIGHTS
        # Generate prologue
        prologue_instructions = self.builder.build_prologue(
            self.used_s_regs, self.local_vars_nb, not self.is_leaf
        )
        self.instructions += prologue_instructions
        self.prologue_size = len(prologue_instructions)
        for _ in range(self.body_size):
            # Add random instructions
            max_offset = (self.body_size - len(self.instructions)) * 4
            instruction = self.builder.build_random_instruction(
                self.registers, max_offset, weights
            )
            self.instructions.append(instruction)
        # Generate epilogue
        epilogue_instructions = self.builder.build_epilogue(
            self.used_s_regs, self.local_vars_nb, not self.is_leaf
        )
        self.instructions += epilogue_instructions
        self.epilogue_size = len(epilogue_instructions)

    def generate(self):
        self.machine_code = [
            instruction.generate() for instruction in self.instructions
        ]
        return self.machine_code

    def generate_bytes(self):
        for instruction in self.instructions:
            self.bytes += instruction.generate_bytes()
        return self.bytes

    def accept_build(self, generator, method_offset):
        return generator.build_method_call(self, method_offset)

    # TODO: Rework with new workflow!
    def patch_calls(self, callees):
        # Check for recursive call
        if self in callees:
            raise_call_patch_recursive_error(self, callees)
        # Check for mutual call
        self.callees = callees
        for callee in callees:
            if self in callee.callees:
                print("removing callee")
                self.callees.remove(callee)

        replacement_nb = min(len(callees), self.call_number)
        # Replace random parts of the method with calls to chosen callees
        indexes = random.sample(range(0, self.body_size - 1, 2), replacement_nb)
        for ind, callee in zip(indexes, self.callees):
            # Compute the offset:
            #    address + (ind + 1) * 4
            #                 ^   ^
            #  compute index /    \ call takes two instructions offset computed from the second
            offset = callee.address - (self.address + ind * 4)
            call_instructions = self.builder.build_method_call(offset)
            # Add the two instructions for the call
            self.instructions[ind] = call_instructions[0]
            self.instructions[ind + 1] = call_instructions[1]
        # print("{} calls to patch with {} (addr {})".format(self.call_number, callees, self.address))
