import datetime
import json
import logging
import os
import random
import shutil
import subprocess
import sys
from typing import List, Mapping, Tuple, Type

from benchmarks.data import (
    CompilationData,
    ConfigData,
    ConsolidationData,
    DumpData,
    EmulationData,
    ExecutionData,
    GenerationData,
    GigueData,
    InputData,
    JITElementsData,
    MethodData,
    PICData,
    RocketInputData,
)
from benchmarks.exceptions import (
    EnvironmentException,
    UnknownIsolationSolutionException,
)
from benchmarks.parser import LogParser
from gigue.constants import INSTRUCTIONS_INFO, InstructionInfo
from gigue.exceptions import BuilderException, GeneratorException, MethodException
from gigue.fixer.fixer_constants import FIXER_INSTRUCTIONS_INFO
from gigue.fixer.fixer_generator import FIXERTrampolineGenerator
from gigue.generator import Generator, TrampolineGenerator
from gigue.helpers import mean
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

    def __init__(self):
        self.parser: LogParser = LogParser()
        # Check environment variables
        try:
            self.check_envs()
        except EnvironmentException as err:
            logger.error(err)
            raise
        # Create missing directories
        if not os.path.exists(Runner.BIN_DIR):
            os.mkdir(Runner.BIN_DIR)
        if not os.path.exists(Runner.RESULTS_DIR):
            os.mkdir(Runner.RESULTS_DIR)
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

    def generate_binary(
        self, seed: int, input_data: InputData
    ) -> Tuple[GenerationData, JITElementsData]:
        # Setup seed
        # \____________

        random.seed(seed)

        # Instanciate generator
        # \______________________

        gen_class: Type[Generator]

        if input_data["isolation_solution"] == "none":
            if input_data["uses_trampolines"]:
                gen_class = TrampolineGenerator
                self.instructions_info = INSTRUCTIONS_INFO
            else:
                gen_class = Generator
                self.instructions_info = INSTRUCTIONS_INFO
        elif input_data["isolation_solution"] == "rimiss":
            assert input_data["uses_trampolines"]
            gen_class = RIMIShadowStackTrampolineGenerator
            self.instructions_info = RIMI_INSTRUCTIONS_INFO
        elif input_data["isolation_solution"] == "rimifull":
            assert input_data["uses_trampolines"]
            gen_class = RIMIFullTrampolineGenerator
            self.instructions_info = RIMI_INSTRUCTIONS_INFO
        elif input_data["isolation_solution"] == "fixer":
            assert input_data["uses_trampolines"]
            gen_class = FIXERTrampolineGenerator
            self.instructions_info = FIXER_INSTRUCTIONS_INFO
        else:
            raise UnknownIsolationSolutionException(
                "This isolation solution is unknown, the ones supported by Gigue are"
                " 'none', 'rimmiss', 'rimifull' and 'fixer'."
            )
        try:
            # Instanciate the generator
            generator: Generator = gen_class(
                # Global info
                registers=input_data["registers"],
                weights=input_data["weights"],
                # Addresses offset
                jit_start_address=input_data["jit_start_address"],
                interpreter_start_address=input_data["interpreter_start_address"],
                # Method info
                jit_size=input_data["jit_size"],
                jit_nb_methods=input_data["jit_nb_methods"],
                method_variation_mean=input_data["method_variation_mean"],
                method_variation_stdev=input_data["method_variation_stdev"],
                # Call info
                call_depth_mean=input_data["call_depth_mean"],
                call_occupation_mean=input_data["call_occupation_mean"],
                call_occupation_stdev=input_data["call_occupation_stdev"],
                # PICs
                pics_ratio=input_data["pics_ratio"],
                pics_mean_case_nb=input_data["pics_mean_case_nb"],
                pics_cmp_reg=input_data["pics_cmp_reg"],
                pics_hit_case_reg=input_data["pics_hit_case_reg"],
                # Data info
                data_reg=input_data["data_reg"],
                data_generation_strategy=input_data["data_generation_strategy"],
                data_size=input_data["data_size"],
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
        methods_call_occupation: List[int] = []
        methods_call_depth: List[int] = []
        pics_case_nb: List[int] = []
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
                methods_call_occupation.append(elt.call_occupation())
                if elt.call_number != 0:
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
                    methods_size.append(method.total_size())
                    methods_call_occupation.append(method.call_occupation())
                    methods_call_depth.append(method.call_depth)
                    # TODO: Should attribute an ID and use it rather than this
                    pic_methods_info.append(pic_method_data)
                pic_data: PICData = {
                    "address": elt.address,
                    "full_size": elt.total_size(),
                    "case_number": elt.case_number,
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
            "nb_methods": generator.method_count,
            "nb_pics": generator.pic_count,
            "mean_method_size": mean(methods_size),
            "mean_method_call_occupation": mean(methods_call_occupation),
            "mean_method_call_depth": mean(methods_call_depth),
            "pics_mean_case_nb": mean(pics_case_nb),
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

    def execute_binary(
        self, start_address: int, ret_address: int, rocket_input_data: RocketInputData
    ) -> ExecutionData:
        # Execute on top of rocket
        rocket_config = rocket_input_data["rocket_config"]
        rocket_max_cycles = rocket_input_data["rocket_max_cycles"]
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
        config_data: ConfigData,
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
            # Dump the config data
            with open(f"{base_name}.config.json", "w") as outfile:
                json.dump(config_data, outfile, indent=2, separators=(",", ": "))
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
            # TODO: Cleanup is performed when loading the config
            # Cleanup
            # subprocess.run(["make", "clean"], timeout=10, check=True)
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
