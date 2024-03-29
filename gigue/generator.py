import logging
import random
from collections import defaultdict
from math import ceil, trunc
from typing import Callable, Dict, List, Optional, Tuple, Union

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
    MutualCallException,
    RecursiveCallException,
    WrongAddressException,
)
from gigue.helpers import (
    align,
    flatten_list,
    generate_poisson,
    generate_trunc_norm,
    generate_zero_truncated_poisson,
)
from gigue.instructions import Instruction
from gigue.method import Method
from gigue.pic import PIC
from gigue.trampoline import Trampoline

logger = logging.getLogger("gigue")


class Generator:
    MAX_CODE_SIZE: int = 2 * 1024 * 1024  # 2mb
    INT_PROLOGUE_SIZE: int = 12  # 10 caller-saved stores + ra store + stack space
    INT_EPILOGUE_SIZE: int = 13  # 10 caller-saved loads + ra load + stack space + ret

    def __init__(
        self,
        # Addresses
        interpreter_start_address: int,
        jit_start_address: int,
        # Method sizing
        jit_size: int,
        jit_nb_methods: int,
        method_variation_mean: float,
        method_variation_stdev: float,
        # Call info
        call_depth_mean: int,
        call_occupation_mean: float,
        call_occupation_stdev: float,
        # PICs info
        pics_ratio: float,
        pics_mean_case_nb: int,
        # Data info
        data_size: int = DATA_SIZE,
        data_generation_strategy: str = "random",
        # PICs registers
        pics_cmp_reg: int = CMP_REG,
        pics_hit_case_reg: int = HIT_CASE_REG,
        # Usable registers
        registers: List[int] = CALLER_SAVED_REG,
        data_reg: int = DATA_REG,
        # Instruction weights
        weights: List[int] = INSTRUCTION_WEIGHTS,
        # File naming
        output_int_bin_file: str = BIN_DIR + "int.bin",
        output_jit_bin_file: str = BIN_DIR + "jit.bin",
        output_data_bin_file: str = BIN_DIR + "data.bin",
        output_ss_bin_file: str = BIN_DIR + "ss.bin",
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

        # Method sizing
        self.jit_size: int = jit_size
        self.jit_nb_methods: int = jit_nb_methods
        # TODO: Raise exception if mean size too small
        self.jit_method_size: int = jit_size // jit_nb_methods
        self.method_variation_mean: float = method_variation_mean
        self.method_variation_stdev: float = method_variation_stdev
        # Call info
        self.call_depth_mean: int = call_depth_mean
        self.call_occupation_mean: float = call_occupation_mean
        self.call_occupation_stdev: float = call_occupation_stdev
        self.call_size: int = 3
        self.interpreter_call_size: int = 3
        # PICs parameters
        self.pics_ratio: float = pics_ratio
        self.pics_mean_case_nb: int = pics_mean_case_nb
        self.pics_hit_case_reg: int = pics_hit_case_reg
        self.pics_cmp_reg: int = pics_cmp_reg

        # Element count
        self.method_count: int = 0
        self.pic_count: int = 0

        # Prologue/Epilogue offsets
        self.method_prologue_offset = 1  # Stack sizing
        self.method_epilogue_offset = 2  # Stack sizing + ret
        # TODO: Rename and dissociate prologue epilogue
        self.method_call_offset = 1  # ra load/store

        # Generation
        self.weights: List[int] = weights
        self.builder: InstructionBuilder = InstructionBuilder()
        self.jit_elements: List[Union[Method, PIC]] = []
        self.jit_instructions: List[Instruction] = []
        self.call_depth_dict: Dict[int, List[Method]] = defaultdict(list)
        self.interpreter_instructions: List[Instruction] = []

        # MC/Bytes/Binary generation
        self.jit_machine_code: List[int] = []
        self.jit_bytes: List[bytes] = []
        self.interpreter_machine_code: List[int] = []
        self.interpreter_bytes: List[bytes] = []
        self.jit_bin: bytes = b""
        self.interpreter_bin: bytes = b""
        self.int_bin_file: str = output_int_bin_file
        self.jit_bin_file: str = output_jit_bin_file

        # Data info
        self.data_size: int = data_size
        self.miner: Dataminer = Dataminer()
        self.data_bin: bytes = b""
        self.data_generation_strategy: str = data_generation_strategy
        self.data_bin_file: str = output_data_bin_file

        # Shadow stack (for subclasses)
        self.ss_bin = b""
        self.ss_bin_file: str = output_ss_bin_file

        logger.debug("👨‍🌾 Generator Instanciated:")
        logger.debug(f" - jit size: {jit_size}")
        logger.debug(f" - methods nb: {jit_nb_methods}")
        logger.debug(
            f" - method variation: mean {method_variation_mean} / std"
            f" {method_variation_stdev}"
        )
        logger.debug(
            f" - call variation: mean {call_occupation_mean} / std"
            f" {call_occupation_stdev}"
        )
        logger.debug(f" - call depth: mean/lambda {call_depth_mean}")

    def log_jit_prefix(self) -> str:
        return "🧺"

    def log_int_prefix(self) -> str:
        return "🥧"

    #  JIT element generation
    # \______________________

    def register_element(self, elt: Union[Method, PIC]):
        if isinstance(elt, Method):
            method: Method = elt
            self.jit_elements.append(method)
            self.call_depth_dict[method.call_depth].append(method)
            self.method_count += 1
        elif isinstance(elt, PIC):
            pic: PIC = elt
            self.jit_elements.append(pic)
            for case_method in pic.methods:
                self.call_depth_dict[case_method.call_depth].append(case_method)
            self.pic_count += 1
            self.method_count += pic.method_nb()

    def generate_method(self, address: int, *args, **kwargs) -> Method:
        # body size = jit method size (bin size / nb of methods) * (1 +- size variation)
        # note: the +- is defined as a one ot of two chance
        size_variation: float = generate_trunc_norm(
            variance=self.method_variation_mean,
            std_dev=self.method_variation_stdev,
            lower_bound=0,
            higher_bound=1.0,
        )
        variation_sign: int = 1 if random.random() > 0.5 else -1
        body_size: int = ceil(
            self.jit_method_size * (1 + variation_sign * size_variation)
        )
        # call number is derived from call occupation:
        # max call nb = body size / call size
        # call nb = call occupation * max call nb
        call_occupation: float = generate_trunc_norm(
            variance=self.call_occupation_mean,
            std_dev=self.call_occupation_stdev,
            lower_bound=0,
            higher_bound=1.0,
        )
        max_call_nb: int = body_size // self.call_size
        call_nb: int = trunc(call_occupation * max_call_nb)
        # call depth follows a Poisson distribution with lambda = mean
        call_depth: int = generate_poisson(self.call_depth_mean) if call_nb > 0 else 0
        try:
            method: Method = Method(
                address=address,
                body_size=body_size,
                call_number=call_nb,
                call_depth=call_depth,
                call_size=self.call_size,
                builder=self.builder,
                prologue_offset=self.method_prologue_offset,
                epilogue_offset=self.method_epilogue_offset,
                call_offset=self.method_call_offset,
            )
            logger.debug(
                f"{self.log_jit_prefix()} {method.log_prefix()} Method added with size"
                f" ({body_size}), call nb ({call_nb} => call occupation"
                f" {call_occupation}) and call depth ({call_depth})"
            )
            logger.debug(
                f"{self.log_jit_prefix()} {method.log_prefix()} Effective call"
                f" occupation: {method.call_occupation()}"
            )
        except CallNumberException as err:
            logger.exception(err)
            raise
        return method

    def generate_leaf_method(self, address: int) -> Method:
        size_variation: float = generate_trunc_norm(
            variance=self.method_variation_mean,
            std_dev=self.method_variation_stdev,
            lower_bound=0,
            higher_bound=1.0,
        )
        variation_sign: int = 1 if random.random() > 0.5 else -1
        body_size: int = ceil(
            self.jit_method_size * (1 + variation_sign * size_variation)
        )
        try:
            method: Method = Method(
                address=address,
                body_size=body_size,
                call_number=0,
                call_depth=0,
                call_size=self.call_size,
                builder=self.builder,
                prologue_offset=self.method_prologue_offset,
                epilogue_offset=self.method_epilogue_offset,
                call_offset=self.method_call_offset,
            )
            logger.debug(
                f"{self.log_jit_prefix()} {method.log_prefix()} Leaf method added with"
                f" size {body_size}"
            )
        except CallNumberException as err:
            logger.exception(err)
            raise
        return method

    def generate_pic(self, address: int, remaining_methods: int) -> PIC:
        cases_nb: int = min(
            generate_zero_truncated_poisson(self.pics_mean_case_nb),
            remaining_methods,
        )
        pic: PIC = PIC(
            address=address,
            case_number=cases_nb,
            hit_case_reg=self.pics_hit_case_reg,
            cmp_reg=self.pics_cmp_reg,
            builder=self.builder,
        )
        method_address: int = pic.address + pic.get_switch_size() * 4
        for _ in range(pic.case_number):
            case_method = self.generate_method(method_address)
            pic.add_method(case_method)
            method_address += case_method.total_size() * 4

            # Note: Do not register the methods here, register the PIC directly
        logger.debug(
            f"{self.log_jit_prefix()} {pic.log_prefix()} PIC added with"
            f" {cases_nb} cases"
        )
        return pic

    #  JIT filling and patching
    # \________________________

    def fill_jit_code(self, start_address: Optional[int] = None) -> None:
        logger.debug("Phase 1: Filling JIT code")
        # start_address is used by subclasses (i.e. add trampolines before)!
        if not start_address:
            start_address = self.jit_start_address
        current_address: int = start_address
        current_method_count: int = 0
        # Add a first leaf method
        leaf_method: Method = self.generate_leaf_method(current_address)
        leaf_method.fill_with_instructions(
            registers=self.registers,
            data_reg=self.data_reg,
            data_size=self.data_size,
            weights=self.weights,
        )
        self.register_element(leaf_method)
        current_address += leaf_method.total_size() * 4
        current_method_count += 1
        # Add other methods
        while current_method_count < self.jit_nb_methods:
            code_type: str = random.choices(
                ["method", "pic"], [1 - self.pics_ratio, self.pics_ratio]
            )[0]
            adder_function: Callable = getattr(Generator, "generate_" + code_type)
            current_element: Union[PIC, Method] = adder_function(
                self, current_address, self.jit_nb_methods - current_method_count
            )
            current_element.fill_with_instructions(
                registers=self.registers,
                data_reg=self.data_reg,
                data_size=self.data_size,
                weights=self.weights,
            )
            self.register_element(current_element)
            current_address += current_element.total_size() * 4
            current_method_count += current_element.method_nb()
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
        elt: Union[Method, PIC]
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

    def build_element_call(self, element: Union[Method, PIC], current_address: int):
        # Extracted to override in subclasses!
        return self.builder.build_element_base_call(
            element, element.address - current_address
        )

    def patch_method_calls(self, method: Method) -> None:
        # Extracted to override in subclasses!
        try:
            method.patch_base_calls(
                self.extract_callees(method.call_depth, method.call_number),
                self.call_size,
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
        prologue_instructions: List[Instruction] = self.build_interpreter_prologue(
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
            call_instructions: List[Instruction] = self.build_interpreter_element_call(
                element, current_address
            )
            self.interpreter_instructions += call_instructions
            current_address += len(call_instructions) * 4
            logger.debug(
                f"{self.log_int_prefix()} {hex(current_address)}: Adding call to JIT"
                f" element at {hex(element.address)}."
            )
        epilogue_instructions: List[Instruction] = self.build_interpreter_epilogue(
            10, 0, True
        )
        # Update sizes
        self.interpreter_prologue_size = len(prologue_instructions)
        self.interpreter_epilogue_size = len(epilogue_instructions)
        self.interpreter_instructions += epilogue_instructions
        if (
            self.interpreter_start_address + len(self.interpreter_instructions * 4)
            > self.jit_start_address
        ):
            raise WrongAddressException(
                "Interpretation loop overwrites JIT binary! Interpreter end address"
                f" ({hex(self.interpreter_start_address)} +"
                f" {hex(len(self.interpreter_instructions) * 4)}) should be lower than"
                f" JIT start address ({hex(self.jit_start_address)})"
            )
        logger.debug("Phase 3: Interpretation loop filled!")

    def build_interpreter_prologue(
        self, used_s_regs: int, local_var_nb: int, contains_call: bool
    ):
        # Extracted to override in subclasses!
        return self.builder.build_prologue(
            used_s_regs=used_s_regs,
            local_var_nb=local_var_nb,
            contains_call=contains_call,
        )

    def build_interpreter_epilogue(
        self, used_s_regs: int, local_var_nb: int, contains_call: bool
    ):
        # Extracted to override in subclasses!
        return self.builder.build_epilogue(
            used_s_regs=used_s_regs,
            local_var_nb=local_var_nb,
            contains_call=contains_call,
        )

    def build_interpreter_element_call(
        self, element: Union[Method, PIC], current_address: int
    ):
        # Extracted to override in subclasses!
        return self.builder.build_element_base_call(
            elt=element, offset=element.address - current_address
        )

    #  Machine code generation
    # \_______________________

    def generate_jit_machine_code(self) -> List[int]:
        self.jit_machine_code = [elt.generate() for elt in self.jit_elements]
        return self.jit_machine_code

    def generate_interpreter_machine_code(self) -> List[int]:
        self.interpreter_machine_code = [
            instr.generate() for instr in self.interpreter_instructions
        ]
        return self.interpreter_machine_code

    #  Bytes generation
    # \________________

    def generate_jit_bytes(self) -> List[bytes]:
        self.jit_bytes = [elt.generate_bytes() for elt in self.jit_elements]
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
        return b"".join(fills)

    def generate_output_binary(self) -> Tuple[bytes, bytes]:
        self.generate_interpreter_binary()
        self.generate_jit_binary()

        self.interpreter_bin += self.generate_fills_binary()
        return self.interpreter_bin, self.jit_bin

    def generate_data_binary(self) -> bytes:
        self.data_bin = self.miner.generate_data(
            self.data_generation_strategy, self.data_size
        )
        return self.data_bin

    def generate_shadowstack_binary(self) -> bytes:
        self.ss_bin = self.miner.generate_data("zeroes", 8)
        return self.ss_bin

    #  Binary Writing
    # \______________

    def write_int_binary(self) -> None:
        with open(self.int_bin_file, "wb") as file:
            file.write(self.interpreter_bin)

    def write_jit_binary(self) -> None:
        with open(self.jit_bin_file, "wb") as file:
            file.write(self.jit_bin)

    def write_data_binary(self):
        with open(self.data_bin_file, "wb") as file:
            file.write(self.data_bin)

    def write_shadowstack_binary(self):
        with open(self.ss_bin_file, "wb") as file:
            file.write(self.ss_bin)

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
        self.write_int_binary()
        self.write_jit_binary()
        self.write_data_binary()
        self.generate_shadowstack_binary()
        self.write_shadowstack_binary()


class TrampolineGenerator(Generator):
    def __init__(
        self,
        interpreter_start_address: int,
        jit_start_address: int,
        jit_size: int,
        jit_nb_methods: int,
        method_variation_mean: float,
        method_variation_stdev: float,
        call_depth_mean: int,
        call_occupation_mean: float,
        call_occupation_stdev: float,
        pics_ratio: float,
        pics_mean_case_nb: int,
        data_size: int = DATA_SIZE,
        data_generation_strategy: str = "random",
        pics_cmp_reg: int = CMP_REG,
        pics_hit_case_reg: int = HIT_CASE_REG,
        registers: List[int] = CALLER_SAVED_REG,
        data_reg: int = DATA_REG,
        weights: List[int] = INSTRUCTION_WEIGHTS,
        output_int_bin_file: str = BIN_DIR + "int.bin",
        output_jit_bin_file: str = BIN_DIR + "jit.bin",
        output_data_bin_file: str = BIN_DIR + "data.bin",
        output_ss_bin_file: str = BIN_DIR + "ss.bin",
    ):
        self.trampolines: List[Trampoline] = []
        self.trampoline_instructions: List[Instruction] = []
        super().__init__(
            interpreter_start_address=interpreter_start_address,
            jit_start_address=jit_start_address,
            jit_size=jit_size,
            jit_nb_methods=jit_nb_methods,
            method_variation_mean=method_variation_mean,
            method_variation_stdev=method_variation_stdev,
            call_depth_mean=call_depth_mean,
            call_occupation_mean=call_occupation_mean,
            call_occupation_stdev=call_occupation_stdev,
            pics_ratio=pics_ratio,
            pics_mean_case_nb=pics_mean_case_nb,
            data_size=data_size,
            data_generation_strategy=data_generation_strategy,
            pics_cmp_reg=pics_cmp_reg,
            pics_hit_case_reg=pics_hit_case_reg,
            registers=registers,
            data_reg=data_reg,
            weights=weights,
            output_int_bin_file=output_int_bin_file,
            output_jit_bin_file=output_jit_bin_file,
            output_data_bin_file=output_data_bin_file,
            output_ss_bin_file=output_ss_bin_file,
        )
        self.interpreter_call_size: int = 5

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
        super().fill_jit_code(start_address=current_address)

    # Calls
    # \____

    def build_interpreter_element_call(
        self, element: Union[Method, PIC], current_address: int
    ):
        call_trampoline_offset: int = self.find_trampoline_offset(
            name="call_jit_elt", current_address=current_address
        )
        # Extracted to override in subclasses!
        return self.builder.build_interpreter_trampoline_call(
            elt=element,
            offset=element.address - current_address,
            call_trampoline_offset=call_trampoline_offset,
        )

    # Code Generation
    # \_______________

    def generate_jit_machine_code(self) -> List[int]:
        # Add machine code for trampolines at the start of JIT code
        super().generate_jit_machine_code()
        self.jit_machine_code = [
            instr.generate() for instr in self.trampoline_instructions
        ] + self.jit_machine_code
        return self.jit_machine_code

    def generate_jit_bytes(self) -> List[bytes]:
        # Add bytes for trampolines at the start of JIT code
        super().generate_jit_bytes()
        self.jit_bytes = [
            instr.generate_bytes() for instr in self.trampoline_instructions
        ] + self.jit_bytes
        return self.jit_bytes
