from gigue.constants import InstructionInfo

RIMI_INSTRUCTIONS_INFO = {
    # Duplicated loads
    "lb1": InstructionInfo("lb1", 0b0000011, 0b000, "I"),
    "lbu1": InstructionInfo("lbu1", 0b0000011, 0b100, "I"),
    "lh1": InstructionInfo("lh1", 0b0000011, 0b001, "I"),
    "lhu1": InstructionInfo("lhu1", 0b0000011, 0b101, "I"),
    "lw1": InstructionInfo("lw1", 0b0000011, 0b010, "I"),
    "lwu1": InstructionInfo("lwu1", 0b0000011, 0b110, "I"),
    "ld1": InstructionInfo("ld1", 0b0000011, 0b011, "I"),
    # Duplicated stores
    "sb1": InstructionInfo("sb1", 0b0100011, 0b000, "S"),
    "sh1": InstructionInfo("sh1", 0b0100011, 0b001, "S"),
    "sw1": InstructionInfo("sw1", 0b0100011, 0b010, "S"),
    "sd1": InstructionInfo("sd1", 0b0100011, 0b011, "S"),
    # Domain switching routines
    "jalx": InstructionInfo("jalx", 0b1101111, 0b000, "J"),
    "jalrx": InstructionInfo("jalrx", 0b1100111, 0b000, "I"),
    # Shadow stack instructions
    "sws": InstructionInfo("sws", 0b0100011, 0b010, "S"),
    "lws": InstructionInfo("lws", 0b0110011, 0b000, "I"),
}
