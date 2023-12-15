import logging
import random
from typing import List

from gigue.builder import InstructionBuilder
from gigue.exceptions import (
    BuilderException,
    CallNumberException,
    EmptySectionException,
    MutualCallException,
    RecursiveCallException,
)
from gigue.instructions import Instruction

logger = logging.getLogger("gigue")


class Method:
    def __init__(
        self,
        address: int,
        body_size: int,
        call_number: int,
        builder: InstructionBuilder,
        call_size: int = 3,
        call_depth: int = 1,
        used_s_regs: int = 1,
        local_vars_nb: int = 2,
    ):
        self.address: int = address
        self.body_size: int = body_size
        self.call_depth: int = call_depth
        self.call_size: int = call_size
        self.used_s_regs: int = used_s_regs
        self.local_vars_nb: int = local_vars_nb

        max_call_number = Method.compute_max_call_number(self.body_size, self.call_size)
        if call_number > max_call_number:
            raise CallNumberException(
                f"Call number should be <= {max_call_number} and is {call_number}."
                + "\n  Number of calls in a method cannot be greater than size // 3 "
                + "\n  (note: //3 because a call is composed of max three"
                " instructions in"
                " PICs)."
            )
        self.call_number: int = call_number

        self.is_leaf: bool = self.call_number == 0
        self.prologue_size: int = 0
        self.epilogue_size: int = 0

        self.builder: InstructionBuilder = builder
        self.instructions: List[Instruction] = []
        self.callees: List[Method] = []
        self.callers: List[Method] = []
        self.machine_code: List[int] = []
        self.bytes: bytes = b""

    # Helpers
    # \_______

    @classmethod
    def compute_max_call_number(cls, body_size, call_size):
        # The calls will be added once random instructions are generated to
        # fill the method body. As a call takes two instructions (as a basis)
        # but can be larger (i.e. when using trampolines), it has to be passed
        # as an argument
        return body_size // call_size

    def log_prefix(self):
        return f"🍎 {hex(self.address)}:"

    def get_callees(self):
        return self.callees

    def total_size(self):
        if self.prologue_size == 0 or self.epilogue_size == 0:
            raise EmptySectionException("Prologue or epilogue has not been set.")
        return self.body_size + self.prologue_size + self.epilogue_size

    def call_occupation(self):
        return self.call_number * self.call_size / self.body_size

    def method_nb(self):
        return 1

    # Instruction Filling
    # \___________________

    def fill_with_nops(self):
        for _ in range(self.body_size):
            self.instructions.append(self.builder.build_nop())

    def fill_prologue(self):
        prologue_instructions = self.builder.build_prologue(
            used_s_regs=self.used_s_regs,
            local_var_nb=self.local_vars_nb,
            contains_call=not self.is_leaf,
        )
        self.instructions += prologue_instructions
        self.prologue_size = len(prologue_instructions)

    def fill_body(self, registers, data_reg, data_size, call_size, weights):
        for _ in range(self.body_size):
            # Add random instructions
            max_offset = (
                self.body_size + self.prologue_size - len(self.instructions)
            ) * 4
            # Weights = [R, I, U, J, B]
            instruction = self.builder.build_random_instruction(
                registers=registers,
                max_offset=max_offset,
                data_reg=data_reg,
                data_size=data_size,
                weights=weights,
                call_size=call_size,
            )
            self.instructions.append(instruction)

    def fill_epilogue(self):
        epilogue_instructions = self.builder.build_epilogue(
            self.used_s_regs, self.local_vars_nb, not self.is_leaf
        )
        self.instructions += epilogue_instructions
        self.epilogue_size = len(epilogue_instructions)

    def fill_with_instructions(self, registers, data_reg, data_size, weights):
        logger.debug(f"{self.log_prefix()} Filling method.")
        # Fill prologue
        self.fill_prologue()
        # Generate random instructions
        self.fill_body(
            registers=registers,
            data_reg=data_reg,
            data_size=data_size,
            weights=weights,
            call_size=3,
        )
        # Generate epilogue
        self.fill_epilogue()
        logger.debug(f"{self.log_prefix()} Method filled.")

    # Generation
    # \__________

    def generate(self):
        self.machine_code = [
            instruction.generate() for instruction in self.instructions
        ]
        return self.machine_code

    def generate_bytes(self):
        for instruction in self.instructions:
            self.bytes += instruction.generate_bytes()
        return self.bytes

    # Call-related methods
    # \____________________

    def accept_build_base_call(self, offset):
        try:
            instrs = self.builder.build_method_base_call(offset)
        except BuilderException as err:
            logger.exception(err)
            raise
        return instrs

    def accept_build_interpreter_call(self, offset, call_trampoline_offset):
        try:
            instrs = self.builder.build_interpreter_trampoline_method_call(
                offset=offset,
                call_trampoline_offset=call_trampoline_offset,
            )
        except BuilderException as err:
            logger.exception(err)
            raise
        return instrs

    # Call Patching
    # \_____________

    def check_callees(self, callees):
        # Check for recursive call
        if self in callees:
            raise RecursiveCallException(
                f"Infinite call loop as {self} is in {callees}."
            )
        # Check correct length
        if len(callees) != self.call_number:
            raise CallNumberException(
                f"Incorrect number of callees in method: got {len(callees)},"
                f" expecting {self.call_number}"
            )
        # Check for mutual call
        for callee in callees:
            callee.callers.append(self)
            if self in callee.get_callees():
                raise MutualCallException(
                    f"Mutual call between method at {self.address} and"
                    f" callee at {callee.address}"
                )

    def select_paching_indexes(self, call_size):
        indexes = random.sample(
            # Starting the sizing from the end helps dimension random b/j instructions
            # so they do not land in the middle of a call (as they have the max offset)
            # note: other way around
            # range(self.prologue_size, self.prologue_size + self.body_size - 1,  3)
            range(
                self.prologue_size + self.body_size - call_size,
                self.prologue_size - 1,
                -call_size,
            ),
            len(self.callees),
        )
        return indexes

    def patch_base_calls(self, callees):
        logger.debug(f"{self.log_prefix()} Patching method base calls.")
        self.check_callees(callees)
        self.callees = callees

        # Replace random parts of the method with calls to chosen callees
        # The different argument of the range aim the method body size and goes 3 by 3
        indexes = self.select_paching_indexes(call_size=3)
        for ind, callee in zip(indexes, self.callees):
            # Compute the offset
            offset = callee.address - (self.address + ind * 4)
            # print(
            #     f"Offset: {hex(callee.address)} - ({hex(self.address)}
            #     + {hex(ind*4)}) = {hex(offset)}"
            # )
            call_instructions = self.builder.build_element_base_call(callee, offset)
            # Add call instructions (2 to 3 instructions!)
            self.instructions[ind : ind + len(call_instructions)] = call_instructions

        logger.debug(
            f"{self.log_prefix()} Method base calls patched and callers updated."
        )
