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
from gigue.fixer.fixer_builder import FIXERInstructionBuilder
from gigue.fixer.fixer_constants import FIXER_CMP_REG
from gigue.generator import TrampolineGenerator


class FIXERTrampolineGenerator(TrampolineGenerator):
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
        fixer_cmp_reg: int = FIXER_CMP_REG,
        weights: List[int] = INSTRUCTION_WEIGHTS,
        output_int_bin_file: str = BIN_DIR + "int.bin",
        output_jit_bin_file: str = BIN_DIR + "jit.bin",
        output_data_bin_file: str = BIN_DIR + "data.bin",
    ):
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
        )
        self.builder: FIXERInstructionBuilder = FIXERInstructionBuilder()
        self.fixer_cmp_reg: int = fixer_cmp_reg
        self.registers: List[int] = [
            reg for reg in self.registers if reg != self.fixer_cmp_reg
        ]

        # Prologue/Epilogue offsets
        self.call_size += 3
        print(self.call_size)
        self.method_epilogue_offset += 3

    def build_interpreter_prologue(
        self, used_s_regs: int, local_var_nb: int, contains_call: bool
    ):
        return super(FIXERInstructionBuilder, self.builder).build_prologue(
            used_s_regs=used_s_regs,
            local_var_nb=local_var_nb,
            contains_call=contains_call,
        )

    def build_interpreter_epilogue(
        self, used_s_regs: int, local_var_nb: int, contains_call: bool
    ):
        return super(FIXERInstructionBuilder, self.builder).build_epilogue(
            used_s_regs=used_s_regs,
            local_var_nb=local_var_nb,
            contains_call=contains_call,
        )
