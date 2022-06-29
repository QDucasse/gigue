from gigue.builder import InstructionBuilder
from gigue.constants import INSTRUCTION_WEIGHTS


class Method:
    MAX_METHOD_SIZE = 30
    MAX_CALL_NUMBER = 5
    MAX_CASE_NUMBER = 5

    def __init__(self, size, call_number, address, registers: list):
        # TODO: Should raise errors instead of handling against max size?
        self.address = address
        self.size = min(size, Method.MAX_METHOD_SIZE)

        # The calls will be added once random instructions are generated to
        # fill the method body. As a call takes two instructions and the method
        # should end with a ret, the max number of calls is (size -1) // 2 for
        # a given method size.
        self.call_number = min(call_number, Method.MAX_CALL_NUMBER, (size - 1) // 2)

        self.registers = registers

        self.builder = InstructionBuilder()
        self.instructions = []
        self.machine_code = []
        self.callees = []
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
        # TODO: Should be ret
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


class PIC:
    def __init__(self, case_number, method_size, address, registers):
        self.case_number = case_number
        self.address = address
        self.registers = registers

        self.builder = InstructionBuilder()
        self.switch_instructions = []
        self.pic_instructions = []
        self.methods = []
        self.bytes = b''

    def add_method_instructions(self):
        pass

    def add_switch_instructions(self):
        pass

    def generate(self):
        return


if __name__ == "__main__":
    ib = InstructionBuilder()
    ib.build_random_r_instruction([5, 6, 7])
