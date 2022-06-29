from gigue.builder import InstructionBuilder
from gigue.constants import INSTRUCTION_WEIGHTS


class Method:

    def __init__(self, size, call_number, address, registers: list):
        # TODO: Should raise errors instead of handling against max size?
        self.address = address
        self.size = size

        # TODO: Calls
        # The calls will be added once random instructions are generated to
        # fill the method body. As a call takes two instructions and the method
        # should end with a ret, the max number of calls is (size -1) // 2 for
        # a given method size.
        self.call_number = call_number

        self.registers = registers

        self.builder = InstructionBuilder()
        self.instructions = []
        self.callees = []
        self.machine_code = []
        self.bytes = b''

    def fill_with_nops(self):
        for current_address in range(self.address, self.address + self.size * 4, 4):
            self.instructions.append(self.builder.build_nop())

    def add_instructions(self, weights=None):
        # Weights = [R, I, U, J, B]
        if weights is None:
            weights = INSTRUCTION_WEIGHTS
        for current_address in range(self.address, self.address + (self.size - 1) * 4, 4):
            # Add random instructions
            max_offset = self.address + self.size * 4 - current_address
            instruction = self.builder.build_random_instruction(
                self.registers, max_offset, weights
            )
            self.instructions.append(instruction)
        self.instructions.append(self.builder.build_ret())

    def generate(self):
        self.machine_code = [instruction.generate() for instruction in self.instructions]
        return self.machine_code

    def generate_bytes(self):
        for instruction in self.instructions:
            self.bytes += instruction.generate_bytes()
        return self.bytes

    # def patch_calls(self, callees):
    #     # Replace random parts of the
    #     self.callees = callees
