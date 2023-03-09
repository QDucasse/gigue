import pytest

from gigue.constants import INSTRUCTIONS_INFO
from gigue.disassembler import Disassembler
from gigue.fixer.constants import FIXER_INSTRUCTIONS_INFO
from tests.conftest import Handler


class FIXERHandler(Handler):
    def handle_cficall(uc_emul):
        print("Handled cficall.")

    def handle_cfiret(uc_emul):
        print("Handled cfiret.")


@pytest.fixture
def fixer_disasm_setup():
    disassembler = Disassembler(INSTRUCTIONS_INFO | FIXER_INSTRUCTIONS_INFO)
    return disassembler


@pytest.fixture
def fixer_handler_setup(fixer_disasm_setup):
    return FIXERHandler(fixer_disasm_setup)
