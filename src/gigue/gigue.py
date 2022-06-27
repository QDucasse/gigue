from gigue.method import PIC
from gigue.method import Method


class Gigue:
    def __init__(self, method_nub):
        self.methods = []
        self.pics = []

    def generate_jit_code(self):
        # methods + pics
        self.methods.append(Method())
        self.pics.append(PIC())

    def generate_interpetation_loop(self):
        # for all addresses in methods and pics, generate a call
        pass
