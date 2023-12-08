"""
Module that contains the command line app.

Why does this file exist, and why not put this in __main__?

You might be tempted to import things from __main__ later, but that will cause
problems: the code will get executed twice:

- When you run `python -m gigue` python will execute
``__main__.py`` as a script. That means there won't be any
``gigue.__main__`` in ``sys.modules``.
- When you import __main__ it will get executed again (as a module) because
there's no ``gigue.__main__`` in ``sys.modules``.

Also see (1) from http://click.pocoo.org/5/setuptools/#setuptools-integration
"""

import argparse
import datetime
import logging
import os
import sys
from typing import List, Optional

from gigue.helpers import bytes_to_int
from toccata.data import (
    CompilationData,
    ConfigData,
    ConsolidationData,
    ExecutionData,
    FullData,
    GenerationData,
    JITElementsData,
    RunData,
)
from toccata.exceptions import IncorrectSeedsNumberException
from toccata.runner import Runner

logger = logging.getLogger("toccata")
logger.setLevel(logging.INFO)

nbmethods = {
    "low": {
        "jit_nb_methods": 75,
    },
    "medium": {
        "jit_nb_methods": 175,
    },
    "high": {
        "jit_nb_methods": 275,
    },
}

calloccup = {
    "low": {
        "call_depth_mean": 1,
        "call_occupation_mean": 0.01,
        "call_occupation_stdev": 0.01,
    },
    "medium": {
        "call_depth_mean": 2,
        "call_occupation_mean": 0.03,
        "call_occupation_stdev": 0.03,
    },
    "high": {
        "call_depth_mean": 3,
        "call_occupation_mean": 0.1,
        "call_occupation_stdev": 0.1,
    },
}

memaccess = {
    "low": {
        "weights": [28, 28, 20, 8, 8, 4, 4],
    },
    "medium": {
        "weights": [20, 20, 20, 8, 8, 12, 12],
    },
    "high": {
        "weights": [20, 20, 4, 8, 8, 20, 20],
    },
}


def apply_fields_to_conf(fields, config: ConfigData):
    for field, value in fields.items():
        try:
            config["input_data"][field] = value  # type: ignore
        except KeyError as err:
            logger.exception(err)
            logger.exception(
                "This class of instruction is not defined in the available ones,"
                " see InstrClassData."
            )
            raise


class Parser(argparse.ArgumentParser):
    def __init__(self):
        super(Parser, self).__init__(description="Toccata, benchmark runner")
        self.add_parse_arguments()

    def add_parse_arguments(self):
        self.add_argument(
            "-f",
            "--fileconf",
            type=str,
            default=f"{Runner.CONFIG_DIR}base_config.json",
            help="Complete config to use, usable as the only CLI argument",
        )

        self.add_argument(
            "-i",
            "--isolation",
            default="",
            help="Isolation technique to use",
        )

        self.add_argument(
            "-e",
            "--emulator",
            default="",
            help="Core emulator running the experiments",
        )

        self.add_argument(
            "-r",
            "--runs",
            type=int,
            default=0,
            help="Run number for this config",
        )

        possible_choices = ["low", "medium", "high"]
        self.add_argument(
            "-n",
            "--nbmethods",
            type=str,
            default="",
            choices=possible_choices,
            help="Method number",
        )

        self.add_argument(
            "-s",
            "--seeds",
            action="append",
            default=[],
            help=(
                "Seeds for each run (should have a length equal to the number of runs)"
            ),
        )

        group = self.add_mutually_exclusive_group()
        group.add_argument(
            "-c",
            "--calloccup",
            type=str,
            default="",
            choices=possible_choices,
            help="Call occupation",
        )

        group.add_argument(
            "-m",
            "--memaccess",
            type=str,
            default="",
            choices=possible_choices,
            help="Memory accesses",
        )

    def parse(self, args):
        return self.parse_args(args)


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = Parser()
    args = parser.parse(argv)

    if not argv:
        parser.print_help()
        return 0

    runner: Runner = Runner()
    config_data: ConfigData
    config_name: str

    # Check if the config subcommand is activated
    logger.info("Loading config...")
    # 1. Load the base config file
    config_file: str = args.fileconf
    config_data = runner.load_config(config_file=config_file)
    config_name = config_file.split("/")[-1].split(".")[0]

    # 2. Use cli args to alter the config
    # 2.1 Number of runs and their seeds
    if args.runs > 0:
        config_data["nb_runs"] = args.runs
    if args.seeds:
        if len(args.seeds) != config_data["nb_runs"]:
            raise IncorrectSeedsNumberException(
                "Number of specified seeds is incorrect. The config file should"
                " hold the same number of seeds and runs, if no seed are specified,"
                " please use an empty list '[]'."
            )
        else:
            config_data["run_seeds"] = args.seeds

    # 2.2 Isolation
    if args.isolation:
        config_data["input_data"]["isolation_solution"] = args.isolation

    # 2.3 Core selection
    if args.emulator:
        config_data["input_data"]["core"] = args.emulator

    # 2.2 Other parameters
    parameters = ["nbmethods", "calloccup", "memaccess"]
    for parameter in parameters:
        if getattr(args, parameter):
            apply_fields_to_conf(
                globals()[parameter][getattr(args, parameter)], config_data
            )
            config_name += (
                f"{'_' if config_name else ''}{getattr(args, parameter)}_{parameter}"
            )

    # 3. Format result directory name
    now: datetime.datetime = datetime.datetime.now()
    formatted_date: str = now.strftime("%Y-%m-%d_%H-%M-%S")
    base_dir_name: str = f"{Runner.RESULTS_DIR}{formatted_date}_{config_name}/"

    # 4. Setup seeds
    nb_runs: int = config_data["nb_runs"]
    run_seeds: List[int] = config_data["run_seeds"]
    if len(run_seeds) == 0:
        run_seeds = [bytes_to_int(os.urandom(16)) for _ in range(nb_runs)]
        config_data["run_seeds"] = run_seeds
    if len(run_seeds) != nb_runs:
        raise IncorrectSeedsNumberException(
            "Number of specified seeds is incorrect. The config file should hold the"
            " same number of seeds and runs, if no seed are specified, please use an"
            " empty list '[]'."
        )

    # 5. Launch the runs
    full_data: FullData = {"config_data": config_data, "run_data": []}
    for run_number in range(nb_runs):
        logger.info(f"Run {run_number + 1} out of {nb_runs}")
        # 5.1 Generate binary
        seed: int = run_seeds[run_number]
        generation_data: GenerationData
        jit_elements_data: JITElementsData
        logger.info("Generating binary...")
        generation_data, jit_elements_data = runner.generate_binary(
            seed, config_data["input_data"]
        )
        if not runner.generation_ok:
            logger.warning("Generation failed, skipping to next run...")
            continue
        # 5.2 Compile binary
        logger.info("Compiling binary...")
        compilation_data: CompilationData = runner.compile_binary()
        if not runner.compilation_ok:
            logger.warning("Compilation failed, skipping to next run...")
            continue
        # 5.3 Execute binary
        logger.info("Executing binary...")
        execution_data: ExecutionData = runner.execute_binary(
            start_address=compilation_data["dump_data"]["start_address"],
            ret_address=compilation_data["dump_data"]["ret_address"],
            max_cycles=config_data["input_data"]["max_cycles"],
            core=config_data["input_data"]["core"],
        )
        if not runner.execution_ok:
            logger.warning("Execution failed, skipping to next run...")
            continue
        # 5.4 Consolidate logs
        logger.info("Consolidating logs and agglomerating data...")
        consolidation_data: ConsolidationData = runner.consolidate_logs(
            base_dir_name=base_dir_name,
            config_name=config_name,
            run_number=run_number,
            jit_elements_data=jit_elements_data,
            config_data=config_data,
        )
        # 5.5 Agglomerate data
        run_data: RunData = {
            "run_number": run_number,
            "generation_data": generation_data,
            "compilation_data": compilation_data,
            "execution_data": execution_data,
            "consolidation_data": consolidation_data,
        }
        full_data["run_data"].append(run_data)
        # 6. Store data
        runner.store_gigue_data(
            gigue_data=full_data, data_file=f"{base_dir_name}data.json"
        )
    return 0
