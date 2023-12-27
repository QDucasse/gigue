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
from gigue.rimi.rimi_constants import RIMI_SSP_REG, SHADOW_STACK_SIZE


class RIMIShadowStackTrampolineGenerator(TrampolineGenerator):
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
        shadow_stack_size: int = SHADOW_STACK_SIZE,
        pics_cmp_reg: int = CMP_REG,
        pics_hit_case_reg: int = HIT_CASE_REG,
        registers: List[int] = CALLER_SAVED_REG,
        data_reg: int = DATA_REG,
        rimi_ssp_reg: int = RIMI_SSP_REG,
        weights: List[int] = INSTRUCTION_WEIGHTS,
        output_int_bin_file: str = BIN_DIR + "int.bin",
        output_jit_bin_file: str = BIN_DIR + "jit.bin",
        output_data_bin_file: str = BIN_DIR + "data.bin",
        output_ss_bin_file: str = BIN_DIR + "ss.bin",
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
            output_ss_bin_file=output_ss_bin_file,
        )
        self.builder: RIMIShadowStackInstructionBuilder = (
            RIMIShadowStackInstructionBuilder()
        )
        self.rimi_ssp_reg: int = rimi_ssp_reg
        self.registers: List[int] = [
            reg for reg in self.registers if reg != self.rimi_ssp_reg
        ]

        self.shadow_stack_size = shadow_stack_size

    def build_interpreter_prologue(
        self, used_s_regs: int, local_var_nb: int, contains_call: bool
    ):
        # Use the base prologue setup, (using non-duplicated sd)
        return super(RIMIShadowStackInstructionBuilder, self.builder).build_prologue(
            used_s_regs=used_s_regs,
            local_var_nb=local_var_nb,
            contains_call=contains_call,
        )

    def build_interpreter_epilogue(
        self, used_s_regs: int, local_var_nb: int, contains_call: bool
    ):
        # Use the base epilogue (using non-duplicated ld)
        return super(RIMIShadowStackInstructionBuilder, self.builder).build_epilogue(
            used_s_regs=used_s_regs,
            local_var_nb=local_var_nb,
            contains_call=contains_call,
        )

    def generate_shadowstack_binary(self) -> bytes:
        self.ss_bin = self.miner.generate_data("zeroes", self.shadow_stack_size)
        return self.ss_bin


class RIMIFullTrampolineGenerator(RIMIShadowStackTrampolineGenerator):
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
        shadow_stack_size: int = SHADOW_STACK_SIZE,
        pics_cmp_reg: int = CMP_REG,
        pics_hit_case_reg: int = HIT_CASE_REG,
        registers: List[int] = CALLER_SAVED_REG,
        data_reg: int = DATA_REG,
        rimi_ssp_reg: int = RIMI_SSP_REG,
        weights: List[int] = INSTRUCTION_WEIGHTS,
        output_int_bin_file: str = BIN_DIR + "int.bin",
        output_jit_bin_file: str = BIN_DIR + "jit.bin",
        output_data_bin_file: str = BIN_DIR + "data.bin",
        output_ss_bin_file: str = BIN_DIR + "ss.bin",
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
            shadow_stack_size=shadow_stack_size,
            pics_cmp_reg=pics_cmp_reg,
            pics_hit_case_reg=pics_hit_case_reg,
            registers=registers,
            data_reg=data_reg,
            rimi_ssp_reg=rimi_ssp_reg,
            weights=weights,
            output_int_bin_file=output_int_bin_file,
            output_jit_bin_file=output_jit_bin_file,
            output_data_bin_file=output_data_bin_file,
            output_ss_bin_file=output_ss_bin_file,
        )
        self.builder: RIMIFullInstructionBuilder = RIMIFullInstructionBuilder()

    # def patch_method(self, method: Method):
    #     replacement = {
    #         "lb": RIMIIInstruction.lb1,
    #         "lbu": RIMIIInstruction.lbu1,
    #         "lh": RIMIIInstruction.lh1,
    #         "lhu": RIMIIInstruction.lhu1,
    #         "lw": RIMIIInstruction.lw1,
    #         "lwu": RIMIIInstruction.lwu1,
    #         "ld": RIMIIInstruction.ld1,
    #         "sb": RIMISInstruction.sb1,
    #         "sh": RIMISInstruction.sh1,
    #         "sw": RIMISInstruction.sw1,
    #         "sd": RIMISInstruction.sd1,
    #     }
    #     new_instructions: List[Instruction] = []
    #     for i, instruction in enumerate(method.instructions):
    #         if (
    #             isinstance(instruction, SInstruction)
    #             and instruction.name == "sd"
    #             and instruction.rs2 == 1
    #         ):
    #             new_instructions.append(
    #                 IInstruction.addi(rd=RIMI_SSP_REG, rs1=RIMI_SSP_REG, imm=-8)
    #             )
    #             new_instructions.append(
    #                 RIMISInstruction.sst(rs1=instruction.rs1, rs2=RIMI_SSP_REG, imm=0),
    #             )
    #         elif (
    #             isinstance(instruction, IInstruction)
    #             and instruction.name == "ld"
    #             and instruction.rd == 1
    #         ):
    #             new_instructions.append(
    #                 RIMIIInstruction.lst(rd=instruction.rd, rs1=RIMI_SSP_REG, imm=0),
    #             )
    #             new_instructions.append(
    #                 IInstruction.addi(rd=RIMI_SSP_REG, rs1=RIMI_SSP_REG, imm=8)
    #             )
    #         elif instruction.name in list(replacement.keys()):
    #             if isinstance(instruction, IInstruction):
    #                 new_instructions.append(
    #                     replacement[instruction.name](
    #                         rd=instruction.rd, rs1=instruction.rs1, imm=instruction.imm
    #                     )
    #                 )
    #             if isinstance(instruction, SInstruction):
    #                 new_instructions.append(
    #                     replacement[instruction.name](
    #                         rs1=instruction.rs1,
    #                         rs2=instruction.rs2,
    #                         imm=instruction.imm,
    #                     )
    #                 )
    #         else:
    #             new_instructions.append(instruction)
    #     method.instructions = new_instructions.copy()

    # def patch_jit_rimi(self):
    #     for i, elt in enumerate(self.jit_elements):
    #         if isinstance(elt, PIC):
    #             for method in elt.methods:
    #                 self.patch_method(method)
    #         elif isinstance(elt, Method):
    #             self.patch_method(elt)
