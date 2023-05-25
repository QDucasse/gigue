import datetime
import json
import logging
import os
import random
import shutil
import subprocess
import sys
from typing import List, Mapping, Optional, Tuple, Type

from benchmarks.data import (
    CompilationData,
    ConfigData,
    ConsolidationData,
    DumpData,
    EmulationData,
    ExecutionData,
    FullData,
    GenerationData,
    GigueData,
    JITElementsData,
    MethodData,
    PICData,
    RunData,
)
from benchmarks.exceptions import (
    EnvironmentException,
    IncorrectSeedsNumberException,
    UnknownIsolationSolutionException,
)
from benchmarks.parser import LogParser
from gigue.constants import INSTRUCTIONS_INFO, InstructionInfo
from gigue.exceptions import BuilderException, GeneratorException, MethodException
from gigue.fixer.fixer_constants import FIXER_INSTRUCTIONS_INFO
from gigue.fixer.fixer_generator import FIXERTrampolineGenerator
from gigue.generator import Generator, TrampolineGenerator
from gigue.helpers import bytes_to_int, mean
from gigue.method import Method
from gigue.pic import PIC
from gigue.rimi.rimi_constants import RIMI_INSTRUCTIONS_INFO
from gigue.rimi.rimi_generator import (
    RIMIFullTrampolineGenerator,
    RIMIShadowStackTrampolineGenerator,
)

logger = logging.getLogger("gigue")


class Runner:
    # Directories
    RESULTS_DIR: str = "benchmarks/results/"
    CONFIG_DIR: str = "benchmarks/config/"
    BIN_DIR: str = "bin/"
    LOG_DIR: str = "log/"
    # Files
    ELF_FILE: str = "out.elf"
    DUMP_FILE: str = "out.dump"
    ROCKET_FILE: str = "out.rocket"
    GIGUE_LOG_FILE: str = "gigue.log"

    def __init__(self, config_file: Optional[str]):
        self.parser: LogParser = LogParser()
        # Check environment variables
        try:
            self.check_envs()
        except EnvironmentException as err:
            logger.error(err)
            raise
        if config_file is None:
            config_file = Runner.CONFIG_DIR + "default.json"
        self.config_data: ConfigData = self.load_config(config_file=config_file)
        if not os.path.exists(Runner.BIN_DIR):
            os.mkdir(Runner.BIN_DIR)
        if not os.path.exists(Runner.RESULTS_DIR):
            os.mkdir(Runner.RESULTS_DIR)
        self.input_data = self.config_data["input_data"]
        self.gen_class: Type[Generator] = Generator
        self.instructions_info: Mapping[str, InstructionInfo] = {}
        self.generation_ok: int = 0
        self.compilation_ok: int = 0
        self.dump_ok: int = 0
        self.execution_ok: int = 0

    def check_envs(self) -> None:
        if "RISCV" not in os.environ:
            raise EnvironmentException(
                "RISCV environment variable is not set. Please define it "
                "to point to your installed toolchain location "
                "(i.e. export RISCV=path/to/your/toolchain)"
            )
        if "ROCKET" not in os.environ:
            raise EnvironmentException(
                "ROCKET environment variable is not set. Please define it "
                "to point to the rocket-chip repository "
                "(i.e. export ROCKET=path/to/rocket/repo)"
            )

    def load_config(self, config_file: str) -> ConfigData:
        try:
            subprocess.run(["make", "cleanall"], timeout=10, check=True)
        except (
            FileNotFoundError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
        ) as err:
            logger.error(err)
            raise
        try:
            with open(config_file, "r") as config:
                config_data: ConfigData = json.load(config)
        except EnvironmentError as err:
            logger.error(err)
            raise
        return config_data

    def store_gigue_data(self, gigue_data: GigueData, data_file: str) -> None:
        try:
            with open(data_file, "w") as outfile:
                json.dump(gigue_data, outfile, indent=2, separators=(",", ": "))
        except EnvironmentError as err:
            logger.error(err)
            raise

    def generate_binary(self, seed: int) -> Tuple[GenerationData, JITElementsData]:
        # Setup seed
        # \____________

        random.seed(seed)

        # Instanciate generator
        # \______________________
        if self.input_data["isolation_solution"] == "none":
            if self.input_data["uses_trampolines"]:
                self.gen_class = TrampolineGenerator
                self.instructions_info = INSTRUCTIONS_INFO
            else:
                self.gen_class = Generator
                self.instructions_info = INSTRUCTIONS_INFO
        elif self.input_data["isolation_solution"] == "rimiss":
            assert self.input_data["uses_trampolines"]
            self.gen_class = RIMIShadowStackTrampolineGenerator
            self.instructions_info = RIMI_INSTRUCTIONS_INFO
        elif self.input_data["isolation_solution"] == "rimifull":
            assert self.input_data["uses_trampolines"]
            self.gen_class = RIMIFullTrampolineGenerator
            self.instructions_info = RIMI_INSTRUCTIONS_INFO
        elif self.input_data["isolation_solution"] == "fixer":
            assert self.input_data["uses_trampolines"]
            self.gen_class = FIXERTrampolineGenerator
            self.instructions_info = FIXER_INSTRUCTIONS_INFO
        else:
            raise UnknownIsolationSolutionException(
                "This isolation solution is unknown, the ones supported by Gigue are"
                " 'none', 'rimmiss', 'rimifull' and 'fixer'."
            )
        try:
            # Instanciate the generator
            generator: Generator = self.gen_class(
                # Addresses
                jit_start_address=self.input_data["jit_start_address"],
                interpreter_start_address=self.input_data["interpreter_start_address"],
                # General
                registers=self.input_data["registers"],
                jit_elements_nb=self.input_data["jit_elements_nb"],
                weights=self.input_data["weights"],
                # Data
                data_reg=self.input_data["data_reg"],
                data_generation_strategy=self.input_data["data_generation_strategy"],
                data_size=self.input_data["data_size"],
                # Methods
                method_max_size=self.input_data["method_max_size"],
                max_call_depth=self.input_data["max_call_depth"],
                max_call_nb=self.input_data["max_call_nb"],
                # PICs
                pics_ratio=self.input_data["pics_ratio"],
                pics_method_max_size=self.input_data["pics_method_max_size"],
                pics_max_cases=self.input_data["pics_max_cases"],
                pics_cmp_reg=self.input_data["pics_cmp_reg"],
                pics_hit_case_reg=self.input_data["pics_hit_case_reg"],
            )
            # Generation complete!
            self.generation_ok = 1
        except GeneratorException as err:
            logger.exception(err)
            # Exit run
            self.generation_ok = 0
        try:
            # Generate the binary
            generator.main()
        except (MethodException, BuilderException) as err:
            logger.exception(err)
            # Exit run
            self.generation_ok = 0

        # Fill the generation data
        # \_________________________
        methods_info: List[MethodData] = []
        pics_info: List[PICData] = []
        methods_size: List[int] = []
        methods_call_nb: List[int] = []
        methods_call_depth: List[int] = []
        pics_case_nb: List[int] = []
        pics_methods_size: List[int] = []
        pics_methods_call_nb: List[int] = []
        pics_methods_call_depth: List[int] = []
        for elt in generator.jit_elements:
            if isinstance(elt, Method):
                method_data: MethodData = {
                    "address": elt.address,
                    "full_size": elt.total_size(),
                    "call_number": elt.call_number,
                    "call_depth": elt.call_depth,
                    "used_s_regs": elt.used_s_regs,
                    "local_vars_nb": elt.local_vars_nb,
                }
                methods_info.append(method_data)
                methods_size.append(elt.total_size())
                methods_call_nb.append(elt.call_number)
                methods_call_depth.append(elt.call_depth)
            elif isinstance(elt, PIC):
                pic_methods_info: List[MethodData] = []
                for method in elt.methods:
                    pic_method_data: MethodData = {
                        "address": method.address,
                        "full_size": method.total_size(),
                        "call_number": method.call_number,
                        "call_depth": method.call_depth,
                        "used_s_regs": method.used_s_regs,
                        "local_vars_nb": method.local_vars_nb,
                    }
                    pic_methods_info.append(pic_method_data)
                    pics_methods_size.append(method.total_size())
                    pics_methods_call_nb.append(method.call_number)
                    pics_methods_call_depth.append(method.call_depth)
                pic_data: PICData = {
                    "address": elt.address,
                    "full_size": elt.total_size(),
                    "case_number": elt.case_number,
                    "method_max_size": elt.method_max_size,
                    "method_max_call_number": elt.method_max_call_number,
                    "method_max_call_depth": elt.method_max_call_depth,
                    "methods_info": pic_methods_info,
                }
                pics_info.append(pic_data)
                pics_case_nb.append(elt.case_number)
        jit_elements_data: JITElementsData = {
            "methods_info": methods_info,
            "pics_info": pics_info,
        }

        generation_data: GenerationData = {
            "generation_ok": self.generation_ok,
            "gigue_seed": seed,
            "nb_method": generator.method_count,
            "nb_pics": generator.pic_count,
            "mean_method_size": mean(methods_size),
            "mean_method_call_nb": mean(methods_call_nb),
            "mean_method_call_depth": mean(methods_call_depth),
            "pics_mean_case_nb": mean(pics_case_nb),
            "pics_mean_method_size": mean(pics_methods_size),
            "pics_mean_method_call_nb": mean(pics_methods_call_nb),
            "pics_mean_method_call_depth": mean(pics_methods_call_depth),
        }
        return generation_data, jit_elements_data

    def compile_binary(self) -> CompilationData:
        # Compile binary
        try:
            subprocess.run(["make", "dump"], timeout=10, check=True)
            # Compilation complete!
            self.compilation_ok = 1
        except (
            FileNotFoundError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
        ) as err:
            logger.error(err)
            # Exit run
            self.compilation_ok = 0
        # Parse dump
        dump_data: DumpData = self.parser.parse_dump(Runner.BIN_DIR + Runner.DUMP_FILE)
        compilation_data: CompilationData = {
            "compilation_ok": self.compilation_ok,
            "dump_data": dump_data,
        }
        return compilation_data

    def execute_binary(self, start_address: int, ret_address: int) -> ExecutionData:
        # Execute on top of rocket
        rocket_config = self.input_data["rocket_config"]
        rocket_max_cycles = self.input_data["rocket_max_cycles"]
        try:
            subprocess.run(
                [
                    "make",
                    "exec",
                    f"ROCKET_CYCLES={rocket_max_cycles}",
                    f"ROCKET_CONFIG={rocket_config}",
                ],
                timeout=300,
                check=True,
            )
            # Execution complete!
            self.execution_ok = 1
        except (
            FileNotFoundError,
            subprocess.CalledProcessError,
        ) as err:
            logger.error(err)
            self.execution_ok = 0
        except subprocess.TimeoutExpired as war:
            logger.warning(war)
            self.execution_ok = 1
        # Parse execution logs
        emulation_data: EmulationData = self.parser.parse_rocket_log(
            log_file=Runner.BIN_DIR + Runner.ROCKET_FILE,
            start_address=start_address,
            ret_address=ret_address,
            instructions_info=self.instructions_info,
        )
        execution_data: ExecutionData = {
            "execution_ok": self.execution_ok,
            "emulation_data": emulation_data,
        }
        return execution_data

    def consolidate_logs(
        self,
        base_dir_name: str,
        config_name: str,
        run_number: int,
        jit_elements_data: JITElementsData,
    ) -> ConsolidationData:
        try:
            # Create results directory
            now = datetime.datetime.now()
            formatted_date = now.strftime("%Y-%m-%d_%H-%M-%S")
            run_dir_name = f"{base_dir_name}{run_number}/"
            if run_number == 0 and not os.path.exists(base_dir_name):
                os.makedirs(base_dir_name)
            os.makedirs(run_dir_name)
            # Base name
            base_name: str = (
                f"{run_dir_name}{config_name}_{formatted_date}-{run_number}"
            )
            # Store JIT elements data
            self.store_gigue_data(
                gigue_data=jit_elements_data, data_file=f"{base_name}.json"
            )
            # Copy gigue log
            shutil.copy(
                src=Runner.LOG_DIR + Runner.GIGUE_LOG_FILE,
                dst=f"{base_name}.log",
            )
            # Copy elf
            shutil.copy(
                src=Runner.BIN_DIR + Runner.ELF_FILE,
                dst=f"{base_name}.elf",
            )
            # TODO: TOO BIG!!
            # # Copy dump
            # shutil.copy(
            #     src=Runner.BIN_DIR + Runner.DUMP_FILE,
            #     dst=f"{base_name}.dump",
            # )
            # # Copy exec log
            # shutil.copy(
            #     src=Runner.BIN_DIR + Runner.ROCKET_FILE,
            #     dst=f"{base_name}.rocket",
            # )
            # Cleanup
            subprocess.run(["make", "clean"], timeout=10, check=True)
            consolidation_ok = 1
        except (
            FileNotFoundError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
        ) as err:
            logger.error(err)
            consolidation_ok = 0
        consolidation_data: ConsolidationData = {
            "consolidation_ok": consolidation_ok,
            "run_path": run_dir_name,
        }
        return consolidation_data


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if len(argv) != 1:
        raise OSError(
            "Wrong usage: python -m benchmarks <config_name> (should be in the config"
            " directory)"
        )
    config_file: str = f"{Runner.CONFIG_DIR}{argv[0]}.json"
    runner: Runner = Runner(config_file)
    # TODO: Setup logger to debug
    # Load the config
    config_data: ConfigData = runner.load_config(config_file=config_file)
    config_name: str = config_file.split("/")[-1].split(".")[0]  # for consolidation
    # Format result directory name
    now: datetime.datetime = datetime.datetime.now()
    formatted_date: str = now.strftime("%Y-%m-%d_%H-%M-%S")
    base_dir_name: str = f"{Runner.RESULTS_DIR}{config_name}_{formatted_date}/"
    nb_runs: int = config_data["nb_runs"]
    run_seeds: List[int] = config_data["run_seeds"]
    if len(run_seeds) == 0:
        run_seeds = [bytes_to_int(os.urandom(16)) for _ in range(nb_runs)]
    if len(run_seeds) != nb_runs:
        raise IncorrectSeedsNumberException(
            "Number of specified seeds is incorrect. The config file should hold the"
            " same number of seeds and runs, if no seed are specified, please use an"
            " empty list '[]'."
        )
    # Setup full data
    full_data: FullData = {"config_data": config_data, "run_data": []}
    # Launch the runs
    for run_number in range(nb_runs):
        # Generate binary
        seed: int = run_seeds[run_number]
        generation_data: GenerationData
        jit_elements_data: JITElementsData
        generation_data, jit_elements_data = runner.generate_binary(seed)
        # Compile binary
        compilation_data: CompilationData = runner.compile_binary()
        # Execute binary
        execution_data: ExecutionData = runner.execute_binary(
            start_address=compilation_data["dump_data"]["start_address"],
            ret_address=compilation_data["dump_data"]["ret_address"],
        )
        # Consolidate logs
        consolidation_data: ConsolidationData = runner.consolidate_logs(
            base_dir_name=base_dir_name,
            config_name=config_name,
            run_number=run_number,
            jit_elements_data=jit_elements_data,
        )
        # Agglomerate data
        run_data: RunData = {
            "run_number": run_number,
            "generation_data": generation_data,
            "compilation_data": compilation_data,
            "execution_data": execution_data,
            "consolidation_data": consolidation_data,
        }
        full_data["run_data"].append(run_data)
    runner.store_gigue_data(gigue_data=full_data, data_file=f"{base_dir_name}data.json")
    return 0


if __name__ == "__main__":
    with open(sys.argv[1], "r") as config:
        config_data: ConfigData = json.load(config)

    def max_jit_bin_size(
        nb_elts,
        pics_ratio,
        method_max_size,
        pics_max_cases,
        pics_method_max_size,
        prologue_size,
        epilogue_size,
    ):
        return (
            int(
                nb_elts
                * (1 - pics_ratio)
                * (method_max_size + prologue_size + epilogue_size)
                + nb_elts
                * pics_ratio
                * pics_max_cases
                * (pics_method_max_size + prologue_size + epilogue_size)
            )
            * 4
        )

    nb_elts = config_data["input_data"]["jit_elements_nb"]
    pics_ratio = config_data["input_data"]["pics_ratio"]
    method_max_size = config_data["input_data"]["method_max_size"]
    pics_max_cases = config_data["input_data"]["pics_max_cases"]
    pics_method_max_size = config_data["input_data"]["pics_method_max_size"]
    jit_start_address = config_data["input_data"]["jit_start_address"]
    # Methods: elts * methods ratio * method size (body + epilogue + prologue)
    # PICs: elts * pics ratio * nb case * pic method size (body + epilogue + prologue)
    max_bin_size = (
        max_jit_bin_size(
            nb_elts=nb_elts,
            pics_ratio=pics_ratio,
            method_max_size=method_max_size,
            pics_max_cases=pics_max_cases,
            pics_method_max_size=pics_method_max_size,
            prologue_size=10,
            epilogue_size=10,
        )
        + jit_start_address
    )
    print(
        f"Max binary size: {max_bin_size} bytes, or {max_bin_size / 1024} kB, or"
        f" {max_bin_size / (1024*1024)} mB"
    )
