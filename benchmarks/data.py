from __future__ import annotations

from typing import List, TypedDict


class GigueData(TypedDict):
    pass


class ConfigData(GigueData):
    nb_runs: int
    input_data: InputData


class InputData(GigueData):
    # Global info
    uses_trampolines: int
    isolation_solution: str
    seed: int
    # Addresses offset
    interpreter_start_address: int
    jit_start_address: int
    # General
    jit_elements_nb: int
    registers: List[int]
    # Data info
    data_reg: int
    data_size: int
    data_generation_strategy: str
    # Methods
    method_max_size: int
    max_call_depth: int
    max_call_nb: int
    # PICs
    pics_ratio: float
    pics_method_max_size: int
    pics_max_cases: int
    pics_cmp_reg: int
    pics_hit_case_reg: int
    # Execution info
    rocket_config: str
    rocket_max_cycles: int


class MethodData(GigueData):
    address: int
    body_size: int
    call_number: int
    call_depth: int
    used_s_regs: int
    local_vars_nb: int


class PICData(GigueData):
    address: int
    case_number: int
    method_max_size: int
    method_max_call_number: int
    method_max_call_depth: int
    methods_info: List[MethodData]


class GenerationData(GigueData):
    generation_ok: int
    # Stats on the generation
    gigue_seed: int
    nb_method: int
    nb_pics: int


class JITElementsData(GigueData):
    methods_info: List[MethodData]
    pics_info: List[PICData]


class CompilationData(GigueData):
    compilation_ok: int
    dump_data: DumpData


class DumpData(GigueData):
    dump_ok: int
    # Binary info
    start_address: int
    ret_address: int
    end_address: int
    bin_size: int
    # Syscalls info?


class ExecutionData(GigueData):
    execution_ok: int
    emulation_data: EmulationData


class EmulationData(GigueData):
    emulation_ok: int
    # Emulation info
    verilator_seed: int
    start_cycle: int
    end_cycle: int
    nb_cycles: int
    # Instruction info?
    # nb_jumps: int
    # nb_custom: int


class ConsolidationData(GigueData):
    consolidation_ok: int
    run_path: str


class RunData(GigueData):
    run_number: int
    generation_data: GenerationData
    compilation_data: CompilationData
    execution_data: ExecutionData
    consolidation_data: ConsolidationData


class FullData(GigueData):
    config_data: ConfigData
    run_data: List[RunData]
