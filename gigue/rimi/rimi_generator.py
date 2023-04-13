from typing import List

from gigue.constants import (
    BIN_DIR,
    CALLER_SAVED_REG,
    CMP_REG,
    DATA_REG,
    DATA_SIZE,
    HIT_CASE_REG,
    INSTRUCTION_WEIGHTS,
)
from gigue.generator import TrampolineGenerator
from gigue.rimi.rimi_builder import (
    RIMIFullInstructionBuilder,
    RIMIShadowStackInstructionBuilder,
)
from gigue.rimi.rimi_constants import RIMI_SSP_REG


class RIMIShadowStackTrampolineGenerator(TrampolineGenerator):
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
        rimi_ssp_reg: int = RIMI_SSP_REG,
        weights: List[int] = INSTRUCTION_WEIGHTS,
        output_bin_file: str = BIN_DIR + "out.bin",
        output_data_bin_file: str = BIN_DIR + "data.bin",
    ):
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
        self.builder: RIMIShadowStackInstructionBuilder = (
            RIMIShadowStackInstructionBuilder()
        )
        self.rimi_ssp_reg: int = rimi_ssp_reg
        self.registers: List[int] = [
            reg for reg in self.registers if reg != self.rimi_ssp_reg
        ]


class RIMIFullTrampolineGenerator(TrampolineGenerator):
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
        rimi_ssp_reg: int = RIMI_SSP_REG,
        weights: List[int] = INSTRUCTION_WEIGHTS,
        output_bin_file: str = BIN_DIR + "out.bin",
        output_data_bin_file: str = BIN_DIR + "data.bin",
    ):
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
        self.builder: RIMIFullInstructionBuilder = RIMIFullInstructionBuilder()
        self.rimi_ssp_reg: int = rimi_ssp_reg
        self.registers: List[int] = [
            reg for reg in self.registers if reg != self.rimi_ssp_reg
        ]
