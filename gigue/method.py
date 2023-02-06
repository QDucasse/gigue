import random
from typing import List

from gigue.builder import InstructionBuilder
from gigue.constants import INSTRUCTION_WEIGHTS
from gigue.instructions import Instruction


def raise_call_number_value_error(call_number, size):
    max_call_number = size // 3
    raise ValueError(
        f"ValueError: Call number should be <= {max_call_number} and is {call_number}."
        + "\n  Number of calls in a method cannot be greater than size // 3 "
        + "\n  (note: //3 because a call is composed of max three instructions in"
        " PICs)."
    )


def raise_call_patch_recursive_error(method, callees):
    raise ValueError(
        "ValueError: infinite call loop as {} is in {}".format(method, callees)
    )


def raise_incorrect_callee_number_error(method, callees):
    raise ValueError(
        f"ValueError: incorrect number of callees in method: got {len(callees)},"
        f" expecting {method.call_nb}"
    )


def raise_mutual_call_error(method, callee):
    raise ValueError(
        f"ValueError: mutual call between method at {method.address} and callee at"
        f" {callee.address}"
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

        self.check_call_number(call_number)
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

    @classmethod
    def compute_max_call_number(cls, body_size):
        # The calls will be added once random instructions are generated to
        # fill the method body. As a call takes two instructions and the method
        # should end with a ret, the max number of calls is body_size // 3 for
        # a given method body size.
        return body_size // 3

    def get_max_call_number(self):
        return Method.compute_max_call_number(self.body_size)

    def check_call_number(self, call_number):
        if call_number > self.get_max_call_number():
            raise_call_number_value_error(call_number, self.body_size)

    def get_callees(self):
        return self.callees

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
            max_offset = (
                self.body_size + self.prologue_size - len(self.instructions)
            ) * 4
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

    def accept_build_call(self, method_offset):
        return self.builder.build_method_call(method_offset)

    def patch_calls(self, callees):
        # Check for recursive call
        if self in callees:
            raise_call_patch_recursive_error(self, callees)
        # Check correct length
        if len(callees) != self.call_number:
            raise_incorrect_callee_number_error(self, callees)
        # Check for mutual call
        for callee in callees:
            if self in callee.get_callees():
                raise_mutual_call_error(self, callee)

        self.callees = callees

        # Replace random parts of the method with calls to chosen callees
        # The different argument of the range aim the method body size and goes 3 by 3
        indexes = random.sample(
            # Starting the sizing from the end helps dimension random b/j instructions
            # so they do not land in the middle of a call (as they have the max offset)
            # note: other way around
            # range(self.prologue_size, self.prologue_size + self.body_size - 1,  3)
            range(self.prologue_size + self.body_size - 3, self.prologue_size - 1, -3),
            len(self.callees),
        )
        for ind, callee in zip(indexes, self.callees):
            # Compute the offset
            offset = callee.address - (self.address + ind * 4)
            # print(
            #     f"Offset: {hex(callee.address)} - ({hex(self.address)} + {hex(ind*4)}) = {hex(offset)}"
            # )
            call_instructions = self.builder.build_element_call(callee, offset)
            # Add the two instructions for the call
            self.instructions[ind : ind + len(call_instructions)] = call_instructions
        # print(
        #     "{} calls to patch with {} (addr {})".format(
        #         self.call_number,
        #         [hex(callee.address) for callee in callees],
        #         self.address,
        #     )
        # )
