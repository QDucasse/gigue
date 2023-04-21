from __future__ import annotations

from typing import List, TypedDict


class ConfigData(TypedDict):
    nb_runs: int
    input_data: InputData


class InputData(TypedDict):
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


class MethodData(TypedDict):
    address: int
    body_size: int
    call_number: int
    call_depth: int
    used_s_regs: int
    local_vars_nb: int


class PICData(TypedDict):
    address: int
    case_number: int
    method_max_size: int
    method_max_call_number: int
    method_max_call_depth: int
    methods_info: List[MethodData]


class GenerationData(TypedDict):
    generation_ok: int
    # Stats on the generation
    gigue_seed: int
    nb_method: int
    nb_pics: int
    methods_info: List[MethodData]
    pics_info: List[PICData]


class CompilationData(TypedDict):
    compilation_ok: int
    dump_data: DumpData


class DumpData(TypedDict):
    dump_ok: int
    # Binary info
    start_address: int
    ret_address: int
    end_address: int
    bin_size: int
    # Syscalls info?


class ExecutionData(TypedDict):
    execution_ok: int
    emulation_data: EmulationData


class EmulationData(TypedDict):
    emulation_ok: int
    # Emulation info
    verilator_seed: int
    start_cycle: int
    end_cycle: int
    nb_cycles: int
    # Instruction info?
    # nb_jumps: int
    # nb_custom: int


class ConsolidationData(TypedDict):
    consolidation_ok: int
    run_path: str


class RunData(TypedDict):
    run_number: int
    generation_data: GenerationData
    compilation_data: CompilationData
    execution_data: ExecutionData
    consolidation_data: ConsolidationData


class FullData(TypedDict):
    config_data: ConfigData
    run_data: List[RunData]
