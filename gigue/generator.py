import logging
import random
from collections import defaultdict
from typing import Callable, Dict, List, Optional, Union

from gigue.builder import InstructionBuilder
from gigue.constants import (
    BIN_DIR,
    CALLER_SAVED_REG,
    CMP_REG,
    DATA_REG,
    DATA_SIZE,
    DEFAULT_TRAMPOLINES,
    HIT_CASE_REG,
    INSTRUCTION_WEIGHTS,
)
from gigue.dataminer import Dataminer
from gigue.exceptions import (
    CallNumberException,
    EmptySectionException,
    MutualCallException,
    RecursiveCallException,
    WrongAddressException,
)
from gigue.helpers import align, flatten_list, gaussian_between
from gigue.instructions import Instruction
from gigue.method import Method
from gigue.pic import PIC
from gigue.trampoline import Trampoline

logger = logging.getLogger(__name__)


class Generator:
    MAX_CODE_SIZE: int = 2 * 1024 * 1024  # 2mb
    INT_PROLOGUE_SIZE: int = 12  # 10 caller-saved stores + ra store + stack space
    INT_EPILOGUE_SIZE: int = 13  # 10 caller-saved loads + ra load + stack space + ret

    def __init__(
        self,
        interpreter_start_address: int,
        jit_start_address: int,
        jit_elements_nb: int,
        max_call_depth: int,
        max_call_nb: int,
        method_max_size: int,
        pics_ratio: float,
        pics_method_max_size: int,
        pics_max_cases: int,
        data_size: int = DATA_SIZE,
        data_generation_strategy: str = "random",
        pics_cmp_reg: int = CMP_REG,
        pics_hit_case_reg: int = HIT_CASE_REG,
        registers: List[int] = CALLER_SAVED_REG,
        data_reg: int = DATA_REG,
        weights: List[int] = INSTRUCTION_WEIGHTS,
        output_bin_file: str = BIN_DIR + "out.bin",
        output_data_bin_file: str = BIN_DIR + "data.bin",
    ):
        # Registers
        self.registers: List[int] = registers

        # Data section info
        self.data_reg: int = data_reg  # Default is x31/t6
        # Remove the data reg from the usable registers
        self.registers = [reg for reg in self.registers if reg != self.data_reg]

        # Addresses:
        # The memory layout in memory will result in a single .text section:
        #    Interpretation loop | nops | JIT functions
        if interpreter_start_address > jit_start_address:
            raise WrongAddressException(
                "Interpretation loop start address (here"
                f" {hex(interpreter_start_address)} should be lower than jit start"
                f" address (here {hex(jit_start_address)}))"
            )

        self.jit_start_address: int = align(jit_start_address, 4)
        self.interpreter_start_address: int = align(interpreter_start_address, 4)

        # Prologue/Epilogue info
        self.interpreter_prologue_size: int = 0
        self.interpreter_epilogue_size: int = 0

        # Global JIT code parameters
        self.jit_elements_nb: int = jit_elements_nb  # Methods + PICs
        self.max_call_depth: int = max_call_depth
        self.max_call_nb: int = max_call_nb
        self.call_size: int = 3
        # Methods parameters
        self.method_max_size: int = method_max_size
        self.method_count: int = 0
        # PICs parameters
        self.pics_ratio: float = pics_ratio
        self.pics_max_cases: int = pics_max_cases
        self.pics_method_max_size: int = pics_method_max_size
        self.pics_hit_case_reg: int = pics_hit_case_reg
        self.pics_cmp_reg: int = pics_cmp_reg
        self.pic_count: int = 0

        # Generation
        self.weights: List[int] = weights
        self.builder: InstructionBuilder = InstructionBuilder()
        self.jit_elements: List[Union[Method, PIC]] = []
        self.jit_instructions: List[Instruction] = []
        self.call_depth_dict: Dict[int, List[Union[Method, PIC]]] = defaultdict(list)
        self.interpreter_instructions: List[Instruction] = []

        # MC/Bytes/Binary generation
        self.jit_machine_code: List[int] = []
        self.jit_bytes: List[bytes] = []
        self.interpreter_machine_code: List[int] = []
        self.interpreter_bytes: List[bytes] = []
        self.jit_bin: bytes = b""
        self.interpreter_bin: bytes = b""
        self.fills_bin: bytes = b""
        self.full_bin: bytes = b""
        self.bin_file: str = output_bin_file

        # Data info
        self.data_size: int = data_size
        self.miner: Dataminer = Dataminer()
        self.data_bin: bytes = b""
        self.data_generation_strategy: str = data_generation_strategy
        self.data_bin_file: str = output_data_bin_file

    def log_jit_prefix(self) -> str:
        return "🧺"

    def log_int_prefix(self) -> str:
        return "🥧"

    #  JIT element generation
    # \______________________

    def add_method(self, address: int) -> Method:
        body_size: int = gaussian_between(self.call_size, self.method_max_size)
        # To force the creation of leaf functions,
        # the gaussian distribution is centered
        # around 0 and the absolute value is used!
        max_call_nb: int = min(
            self.max_call_nb, Method.compute_max_call_number(body_size, self.call_size)
        )
        call_nb: int = abs(gaussian_between(-max_call_nb, max_call_nb))
        call_depth: int = (
            0
            if call_nb == 0
            else abs(gaussian_between(-self.max_call_depth, self.max_call_depth))
        )
        try:
            method: Method = Method(
                address=address,
                body_size=body_size,
                call_number=call_nb,
                call_depth=call_depth,
                call_size=self.call_size,
                builder=self.builder,
            )
            logger.debug(
                f"{self.log_jit_prefix()} {method.log_prefix()} Method added with size"
                f" ({body_size}), call nb ({call_nb}) and call depth ({call_depth})"
            )
        except CallNumberException as err:
            logger.exception(err)
            raise
        self.jit_elements.append(method)
        self.call_depth_dict[call_depth].append(method)
        self.method_count += 1
        return method

    def add_leaf_method(self, address: int) -> Method:
        body_size: int = gaussian_between(3, self.method_max_size)
        try:
            method: Method = Method(
                address=address,
                body_size=body_size,
                call_number=0,
                call_depth=0,
                call_size=self.call_size,
                builder=self.builder,
            )
            logger.debug(
                f"{self.log_jit_prefix()} {method.log_prefix()} Leaf method added with"
                f" size {body_size}"
            )
        except CallNumberException as err:
            logger.exception(err)
            raise
        self.jit_elements.append(method)
        self.call_depth_dict[0].append(method)
        self.method_count += 1
        return method

    def add_pic(self, address: int) -> PIC:
        cases_nb: int = random.randint(2, self.pics_max_cases)
        pic: PIC = PIC(
            address=address,
            case_number=cases_nb,
            method_max_size=self.pics_method_max_size,
            method_max_call_number=self.max_call_nb,
            method_max_call_depth=self.max_call_depth,
            hit_case_reg=self.pics_hit_case_reg,
            cmp_reg=self.pics_cmp_reg,
            call_size=self.call_size,
            builder=self.builder,
        )
        logger.debug(
            f"{self.log_jit_prefix()} {pic.log_prefix()} PIC added with"
            f" {cases_nb} cases"
        )
        self.jit_elements.append(pic)
        for method in pic.methods:
            self.call_depth_dict[method.call_depth].append(method)
        self.pic_count += 1
        return pic

    #  JIT filling and patching
    # \________________________

    def fill_jit_code(self, start_address: Optional[int] = None) -> None:
        logger.debug("Phase 1: Filling JIT code")
        # start_address is used by subclasses (i.e. add trampolines before)!
        if not start_address:
            start_address = self.jit_start_address
        current_address: int = start_address
        current_element_count: int = 0
        # Add a first leaf method
        leaf_method: Method = self.add_leaf_method(current_address)
        leaf_method.fill_with_instructions(
            registers=self.registers,
            data_reg=self.data_reg,
            data_size=self.data_size,
            weights=self.weights,
        )
        try:
            current_address += leaf_method.total_size() * 4
            current_element_count += 1
        except EmptySectionException as err:
            logger.exception(err)
            raise
        # Add other methods
        while current_element_count < self.jit_elements_nb:
            code_type: str = random.choices(
                ["method", "pic"], [1 - self.pics_ratio, self.pics_ratio]
            )[0]
            adder_function: Callable = getattr(Generator, "add_" + code_type)
            current_element: Union[PIC, Method] = adder_function(self, current_address)
            current_element.fill_with_instructions(
                registers=self.registers,
                data_reg=self.data_reg,
                data_size=self.data_size,
                weights=self.weights,
            )
            try:
                current_address += current_element.total_size() * 4
                current_element_count += 1
            except EmptySectionException as err:
                logger.exception(err)
                raise
        logger.debug("Phase 1: JIT code elements filled!")

    def extract_callees(self, call_depth: int, nb: int) -> List[Union[Method, PIC]]:
        # Possible nb callees given a call_depth
        # -> selects callees with smaller call_depth degree
        possible_callees: List[Union[Method, PIC]] = flatten_list(
            [
                self.call_depth_dict[i]
                for i in self.call_depth_dict.keys()
                if i < call_depth
            ]
        )
        return random.choices(possible_callees, k=nb)

    def patch_jit_calls(self) -> None:
        logger.debug("Phase 2: Patching calls")
        for elt in self.jit_elements:
            # Patch PIC -> patch methods in it
            if isinstance(elt, PIC):
                logger.debug(
                    f"{self.log_jit_prefix()} {elt.log_prefix()} Patching PIC calls."
                )
                for method in elt.methods:
                    if method.call_depth == 0:
                        continue
                    self.patch_method_calls(method)
            # Patch Method -> patch directly
            elif isinstance(elt, Method):
                if elt.call_depth == 0:
                    continue
                logger.debug(
                    f"{self.log_jit_prefix()} {elt.log_prefix()} Patching method calls."
                )
                self.patch_method_calls(elt)
        logger.debug("Phase 2: Calls patched!")

    def patch_method_calls(self, method: Method) -> None:
        # Extracted to override in subclasses!
        try:
            method.patch_base_calls(
                self.extract_callees(method.call_depth, method.call_number)
            )
        except (
            RecursiveCallException,
            MutualCallException,
            CallNumberException,
        ) as err:
            logger.exception(err)
            raise

    #  Interpretation loop filling
    # \___________________________

    def fill_interpretation_loop(self) -> None:
        logger.debug("Phase 3: Filling interpretation loop")
        # Build a prologue as if all callee-saved regs are used!
        prologue_instructions: List[Instruction] = self.builder.build_prologue(
            used_s_regs=10, local_var_nb=0, contains_call=True
        )
        self.interpreter_instructions += prologue_instructions
        current_address: int = (
            self.interpreter_start_address + len(prologue_instructions) * 4
        )
        # for all addresses in methods and pics, generate a call
        shuffled_elements: List[Union[Method, PIC]] = self.jit_elements.copy()
        random.shuffle(shuffled_elements)
        for element in shuffled_elements:
            call_instructions: List[Instruction] = self.build_element_call(
                element, current_address
            )
            self.interpreter_instructions += call_instructions
            current_address += len(call_instructions) * 4
            logger.debug(
                f"{self.log_int_prefix()} {hex(current_address)}: Adding call to JIT"
                f" element at {hex(element.address)}."
            )
        epilogue_instructions: List[Instruction] = self.builder.build_epilogue(
            10, 0, True
        )
        # Update sizes
        self.interpreter_prologue_size = len(prologue_instructions)
        self.interpreter_epilogue_size = len(epilogue_instructions)
        self.interpreter_instructions += epilogue_instructions
        logger.debug("Phase 3: Interpretation loop filled!")

    def build_element_call(self, element: Union[Method, PIC], current_address: int):
        # Extracted to override in subclasses!
        return self.builder.build_element_base_call(
            element, element.address - current_address
        )

    #  Machine code generation
    # \_______________________

    def generate_jit_machine_code(self) -> List[int]:
        self.jit_machine_code += [elt.generate() for elt in self.jit_elements]
        return self.jit_machine_code

    def generate_interpreter_machine_code(self) -> List[int]:
        self.interpreter_machine_code += [
            instr.generate() for instr in self.interpreter_instructions
        ]
        return self.interpreter_machine_code

    #  Bytes generation
    # \________________

    def generate_jit_bytes(self) -> List[bytes]:
        self.jit_bytes += [elt.generate_bytes() for elt in self.jit_elements]
        return self.jit_bytes

    def generate_interpreter_bytes(self) -> List[bytes]:
        self.interpreter_bytes = [
            instr.generate_bytes() for instr in self.interpreter_instructions
        ]
        return self.interpreter_bytes

    def generate_jit_binary(self) -> bytes:
        self.jit_bin = b"".join(self.jit_bytes)
        return self.jit_bin

    def generate_interpreter_binary(self) -> bytes:
        self.interpreter_bin = b"".join(self.interpreter_bytes)
        return self.interpreter_bin

    def generate_fills_binary(self) -> bytes:
        fill_size: int = (
            self.jit_start_address
            - (self.interpreter_start_address + len(self.interpreter_machine_code) * 4)
        ) // 4
        fills: List[bytes] = [
            self.builder.build_nop().generate_bytes() for i in range(fill_size)
        ]
        self.fills_bin = b"".join(fills)
        return self.fills_bin

    def generate_output_binary(self) -> bytes:
        self.generate_interpreter_binary()
        self.generate_fills_binary()
        self.generate_jit_binary()

        self.full_bin = self.interpreter_bin + self.fills_bin + self.jit_bin
        return self.full_bin

    def generate_data_binary(self) -> bytes:
        self.data_bin = self.miner.generate_data(
            self.data_generation_strategy, self.data_size
        )
        return self.data_bin

    #  Binary Writing
    # \______________

    def write_binary(self) -> None:
        with open(self.bin_file, "wb") as file:
            file.write(self.full_bin)

    def write_data_binary(self):
        with open(self.data_bin_file, "wb") as file:
            file.write(self.data_bin)

    #  Wrap-up
    # \_______

    def main(self) -> None:
        # Fill
        self.fill_jit_code()
        self.patch_jit_calls()
        self.fill_interpretation_loop()
        # Generate the machine code
        self.generate_jit_machine_code()
        self.generate_interpreter_machine_code()
        # Generate bytes
        self.generate_jit_bytes()
        self.generate_interpreter_bytes()
        # Generate binaries
        self.generate_output_binary()
        self.generate_data_binary()
        # Write binaries
        self.write_binary()
        self.write_data_binary()


class TrampolineGenerator(Generator):
    def __init__(
        self,
        interpreter_start_address: int,
        jit_start_address: int,
        jit_elements_nb: int,
        max_call_depth: int,
        max_call_nb: int,
        method_max_size: int,
        pics_ratio: float,
        pics_method_max_size: int,
        pics_max_cases: int,
        data_size: int = DATA_SIZE,
        data_generation_strategy: str = "random",
        pics_cmp_reg: int = CMP_REG,
        pics_hit_case_reg: int = HIT_CASE_REG,
        registers: List[int] = CALLER_SAVED_REG,
        data_reg: int = DATA_REG,
        weights: List[int] = INSTRUCTION_WEIGHTS,
        output_bin_file: str = BIN_DIR + "out.bin",
        output_data_bin_file: str = BIN_DIR + "data.bin",
    ):
        self.trampolines: List[Trampoline] = []
        self.trampoline_instructions: List[Instruction] = []
        super().__init__(
            interpreter_start_address=interpreter_start_address,
            jit_start_address=jit_start_address,
            jit_elements_nb=jit_elements_nb,
            max_call_depth=max_call_depth,
            max_call_nb=max_call_nb,
            method_max_size=method_max_size,
            pics_ratio=pics_ratio,
            pics_method_max_size=pics_method_max_size,
            pics_max_cases=pics_max_cases,
            data_size=data_size,
            data_generation_strategy=data_generation_strategy,
            pics_cmp_reg=pics_cmp_reg,
            pics_hit_case_reg=pics_hit_case_reg,
            registers=registers,
            data_reg=data_reg,
            weights=weights,
            output_bin_file=output_bin_file,
            output_data_bin_file=output_data_bin_file,
        )
        # /!\ The call size is larger when using trampolines
        self.call_size: int = 6

    # Element adding
    # \______________

    def add_trampoline(self, address: int, name: str) -> Trampoline:
        trampoline: Trampoline = Trampoline(
            name=name, address=address, builder=self.builder
        )
        logger.debug(f"{self.log_jit_prefix()} {trampoline.log_prefix()}")
        self.trampolines.append(trampoline)
        return trampoline

    # Instruction Filling
    # \___________________

    def find_trampoline_offset(self, name: str, current_address: int) -> int:
        try:
            trampoline: Trampoline = list(
                filter(lambda tramp: tramp.name == name, self.trampolines)
            )[0]
        except IndexError as err:
            raise IndexError(f"No trampoline named {name}.") from err
        return trampoline.address - current_address

    def fill_jit_code(self, start_address: Optional[int] = None) -> None:
        logger.debug("Phase 1: Filling JIT code")
        # Add trampolines at the start of the JIT address
        if not start_address:
            start_address = self.jit_start_address
        current_address: int = start_address
        for trampoline_name in DEFAULT_TRAMPOLINES:
            try:
                trampoline: Trampoline = self.add_trampoline(
                    address=current_address,
                    name=trampoline_name,
                )
                trampoline.build()
                self.trampoline_instructions += trampoline.instructions
                current_address += len(trampoline.instructions) * 4
            except AttributeError as err:
                logger.exception(err)
                raise
        # Add elements
        current_element_count: int = 0
        # Add a first leaf method
        leaf_method: Method = self.add_leaf_method(current_address)
        leaf_method.fill_with_trampoline_instructions(
            registers=self.registers,
            data_reg=self.data_reg,
            data_size=self.data_size,
            weights=self.weights,
            ret_trampoline_offset=self.find_trampoline_offset(
                "ret_from_jit_elt", current_address
            ),
        )
        try:
            current_address += leaf_method.total_size() * 4
            current_element_count += 1
        except EmptySectionException as err:
            logger.exception(err)
            raise
        # Add other methods
        while current_element_count < self.jit_elements_nb:
            code_type: str = random.choices(
                ["method", "pic"], [1 - self.pics_ratio, self.pics_ratio]
            )[0]
            adder_function: Callable = getattr(Generator, "add_" + code_type)
            current_element: Union[PIC, Method] = adder_function(self, current_address)
            current_element.fill_with_trampoline_instructions(
                registers=self.registers,
                data_reg=self.data_reg,
                data_size=self.data_size,
                weights=self.weights,
                ret_trampoline_offset=self.find_trampoline_offset(
                    "ret_from_jit_elt", current_address
                ),
            )
            try:
                current_address += current_element.total_size() * 4
                current_element_count += 1
            except EmptySectionException as err:
                logger.exception(err)
                raise
        logger.debug("Phase 1: JIT code elements filled!")

    # Calls
    # \_____

    def build_element_call(self, element: Union[Method, PIC], current_address: int):
        call_trampoline_offset: int = self.find_trampoline_offset(
            name="call_jit_elt", current_address=current_address
        )
        return self.builder.build_element_trampoline_call(
            element, element.address - current_address, call_trampoline_offset
        )

    def patch_method_calls(self, method: Method) -> None:
        # Extracted to override in subclasses!
        try:
            method.patch_trampoline_calls(
                self.extract_callees(
                    call_depth=method.call_depth, nb=method.call_number
                ),
                self.find_trampoline_offset(
                    name="call_jit_elt", current_address=method.address
                ),
            )
        except (
            RecursiveCallException,
            MutualCallException,
            CallNumberException,
        ) as err:
            logger.exception(err)
            raise

    # Generation
    # \__________

    def generate_jit_machine_code(self) -> List[int]:
        # Add machine code for trampolines at the start of JIT code
        self.jit_machine_code = [
            instr.generate() for instr in self.trampoline_instructions
        ]
        self.jit_machine_code += super().generate_jit_machine_code()
        return self.jit_machine_code

    def generate_jit_bytes(self) -> List[bytes]:
        # Add bytes for trampolines at the start of JIT code
        self.jit_bytes = [
            instr.generate_bytes() for instr in self.trampoline_instructions
        ]
        self.jit_bytes += super().generate_jit_bytes()
        return self.jit_bytes
