from gigue.constants import InstructionInfo

RIMI_INSTRUCTIONS_INFO = {
    # TODO: Change correct opcodes!
    "lw1": InstructionInfo("lw1", 0b0110011, 0b000, "I"),
    "sw1": InstructionInfo("sw1", 0b0100011, 0b010, "S"),
}
