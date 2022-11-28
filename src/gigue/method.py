import random

from typing import List

from gigue.builder import InstructionBuilder
from gigue.instructions import Instruction
from gigue.constants import INSTRUCTION_WEIGHTS


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
    def __init__(self, size: int, call_number: int, address: int, registers: List[int]):
        self.address = address
        self.size = size

        # The calls will be added once random instructions are generated to
        # fill the method body. As a call takes two instructions and the method
        # should end with a ret, the max number of calls is (size -1) // 2 for
        # a given method size.
        if call_number > (size - 1) // 2:
            raise_call_number_value_error(call_number, size)
        self.call_number = call_number

        self.registers = registers

        self.builder = InstructionBuilder()
        self.instructions: List[Instruction] = []
        self.callees: List[Method] = []
        self.machine_code: List[int] = []
        self.bytes = b""

    def fill_with_nops(self):
        for _ in range(self.address, self.address + self.size * 4, 4):
            self.instructions.append(self.builder.build_nop())

    def add_instructions(self, weights=None):
        # Weights = [R, I, U, J, B]
        if weights is None:
            weights = INSTRUCTION_WEIGHTS
        for current_address in range(
            self.address, self.address + (self.size - 1) * 4, 4
        ):
            # Add random instructions
            max_offset = self.address + self.size * 4 - current_address
            instruction = self.builder.build_random_instruction(
                self.registers, max_offset, weights
            )
            self.instructions.append(instruction)
        self.instructions.append(self.builder.build_ret())

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
        indexes = random.sample(range(0, self.size - 1, 2), replacement_nb)
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
