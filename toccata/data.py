from __future__ import annotations

from typing import List, TypedDict


class GigueData(TypedDict):
    pass


# PARSER DATA
# \_______________


class DumpParsingData(GigueData):
    start_address: int
    ret_address: int
    end_address: int


class LogParsingData(GigueData):
    sim_seed: int
    start_cycle: int
    end_cycle: int
    executed_instrs: List[str]


# RUNNER DATA
# \_____________


class ConfigData(GigueData):
    nb_runs: int
    run_seeds: List[int]
    config_name: str
    input_data: InputData


class InputData(GigueData):
    # Global info
    uses_trampolines: int
    isolation_solution: str
    registers: List[int]
    weights: List[int]
    # Addresses offset
    interpreter_start_address: int
    jit_start_address: int
    # Method info
    jit_size: int
    jit_nb_methods: int
    method_variation_mean: float
    method_variation_stdev: float
    # Call info
    call_depth_mean: int
    call_occupation_mean: float
    call_occupation_stdev: float
    # PICs
    pics_ratio: float
    pics_mean_case_nb: int
    pics_cmp_reg: int
    pics_hit_case_reg: int
    # Data info
    data_reg: int
    data_size: int
    data_generation_strategy: str
    # Execution info
    core: str
    max_cycles: int


class MethodData(GigueData):
    id: int
    address: int
    full_size: int
    call_number: int
    call_depth: int
    used_s_regs: int
    local_vars_nb: int


class PICData(GigueData):
    id: int
    address: int
    full_size: int
    case_number: int
    methods_info: List[MethodData]


class GenerationData(GigueData):
    generation_ok: int
    # Stats on the generation
    gigue_seed: int
    nb_methods: int
    nb_pics: int
    # Methods info
    mean_method_size: float
    mean_method_call_occupation: float
    # stdev_method_call_occupation: float?
    mean_method_call_depth: float
    # PICS Methods info
    pics_mean_case_nb: float


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
    tracing_data: TracingData


class TracingData(GigueData):
    tracing_ok: int
    instrs_nb: int
    instrs_type: InstrTypeData
    instrs_class: InstrClassData


class InstrTypeData(GigueData):
    I: int
    R: int
    U: int
    B: int
    J: int
    S: int


def default_instr_type_data() -> InstrTypeData:
    return {
        "I": 0,
        "R": 0,
        "U": 0,
        "B": 0,
        "J": 0,
        "S": 0,
    }


class InstrClassData(GigueData):
    arithmetic: int
    branching: int
    memory: int
    custom: int
    internal: int


def default_instr_class_data() -> InstrClassData:
    return {
        "arithmetic": 0,
        "branching": 0,
        "memory": 0,
        "custom": 0,
        "internal": 0,
    }


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


# PLOTTING DATA
# \_______________


class CallApplicationClassData(GigueData):
    name: str
    nb_methods_qualif: str
    call_occupations_qualif: str
    isolation: str
    nb_methods: List[int]
    mean_method_sizes: List[float]
    call_occupations: List[float]
    nb_cycles: List[int]
    cpis: List[float]


class MemoryApplicationClassData(GigueData):
    name: str
    nb_methods_qualif: str
    mem_accesses_qualif: str
    isolation: str
    nb_methods: List[int]
    mean_method_sizes: List[float]
    mem_accesses: List[float]
    nb_cycles: List[int]
    cpis: List[float]


class OverheadCallComparisonData(GigueData):
    name_1: str
    name_2: str
    nb_methods_qualif: str
    call_occupations_qualif: str
    cycle_overhead: List[int]
    cycle_overhead_percent: List[float]
    geomean_cycle_overhead: float
    cpi_overhead: List[float]
    cpi_overhead_percent: List[float]
    geomean_cpi_overhead: float


class OverheadMemoryComparisonData(GigueData):
    name_1: str
    name_2: str
    nb_methods_qualif: str
    mem_accesses_qualif: str
    cycle_overhead: List[int]
    cycle_overhead_percent: List[float]
    geomean_cycle_overhead: float
    cpi_overhead: List[float]
    cpi_overhead_percent: List[float]
    geomean_cpi_overhead: float
