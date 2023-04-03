import logging
from typing import List

from gigue.builder import InstructionBuilder
from gigue.instructions import Instruction

logger = logging.getLogger(__name__)


class Trampoline:
    def __init__(self, name: str, address: int):
        self.address: int = address
        self.name: str = name
        self.builder: InstructionBuilder = InstructionBuilder()
        self.instructions: List[Instruction] = []
        self.machine_code: List[int] = []
        self.bytes: bytes = b""

    # Helpers
    # \_______

    def log_prefix(self) -> str:
        return f"🍵 {hex(self.address)}: {self.name} trampoline"

    # Instruction Building
    # \____________________

    def build(self) -> List[Instruction]:
        try:
            build_trampoline = getattr(
                InstructionBuilder, "build_" + self.name + "_trampoline"
            )
            self.instructions = build_trampoline()
        except AttributeError as err:
            raise AttributeError(
                f"Builder method for trampoline '{self.name}' is not defined."
            ) from err
        return self.instructions

    # Generation
    # \__________

    def generate(self) -> List[int]:
        self.machine_code = [
            instruction.generate() for instruction in self.instructions
        ]
        return self.machine_code

    def generate_bytes(self) -> bytes:
        for instruction in self.instructions:
            self.bytes += instruction.generate_bytes()
        return self.bytes
