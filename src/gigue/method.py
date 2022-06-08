
class Method:
    def __init__(self, size, call_number, address, registers: list):
        # Instance variables for basic attributes and checks
        self.size = size         # TODO: Check against max size
        self.address = address      # TODO: Check against max address
        self.call_number = call_number  # TODO: Check against max call

        # Placeholder for generated machine code
        self.machine_code = []
        # Placeholder to hold addresses
        self.callees = []

    def generate(self):
        # Generate calls

        while len(self.machine_code) < self.size:
            pass


class PIC:
    def __init__(self, case_number, method_size, address):
        self.case_number = case_number
        self.address = address

    def generate(self):
        pass
