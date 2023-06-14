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
import os
import sys
from typing import List, Optional

from benchmarks.data import (
    CompilationData,
    ConfigData,
    ConsolidationData,
    ExecutionData,
    FullData,
    GenerationData,
    JITElementsData,
    RunData,
)
from benchmarks.exceptions import IncorrectSeedsNumberException
from benchmarks.runner import Runner
from gigue.helpers import bytes_to_int

nb_methods = {
    "low": {
        "jit_nb_methods": 5,
    },
    "medium": {
        "jit_nb_methods": 50,
    },
    "high": {
        "jit_nb_methods": 500,
    },
}

call_occup = {
    "low": {
        "call_depth_mean": 1,
        "call_occupation_mean": 0.1,
        "call_occupation_stdev": 0.1,
    },
    "medium": {
        "call_depth_mean": 2,
        "call_occupation_mean": 0.2,
        "call_occupation_stdev": 0.1,
    },
    "high": {
        "call_depth_mean": 3,
        "call_occupation_mean": 0.5,
        "call_occupation_stdev": 0.2,
    },
}

mem_access = {
    "low": {
        "weights": [32, 34, 14, 5, 10, 2, 2],
    },
    "medium": {
        "weights": [25, 30, 10, 5, 10, 10, 10],
    },
    "high": {
        "weights": [20, 20, 7, 5, 8, 20, 20],
    },
}


def apply_fields_to_conf(fields, config: ConfigData):
    for field, value in fields.items():
        config["input_data"][field] = value


class Parser(argparse.ArgumentParser):
    def __init__(self):
        super(Parser, self).__init__(description="Beniguet, gigue benchmark runner")
        self.add_parse_arguments()

    def add_parse_arguments(self):
        subparsers = self.add_subparsers(
            dest="command", parser_class=argparse.ArgumentParser
        )
        config_parser = subparsers.add_parser("config")

        config_parser.add_argument(
            "config",
            type=str,
            default=f"{Runner.CONFIG_DIR}base_config.json",
            help="Complete config to use, usable as the only CLI argument",
        )

        param_parser = subparsers.add_parser("param")
        possible_choices = ["low", "medium", "high"]
        param_parser.add_argument(
            "-n",
            "--nb_methods",
            type=str,
            default="",
            choices=possible_choices,
            help="Method number",
        )

        param_parser.add_argument(
            "-r",
            "--nb_runs",
            type=int,
            default=1,
            help="Run number for this config",
        )

        param_parser.add_argument(
            "-s",
            "--seeds",
            action="append",
            default=[],
            help=(
                "Seeds for each run (should have a length equal to the number of runs)"
            ),
        )

        param_parser.add_argument(
            "-i",
            "--isolation",
            default="none",
            help="Isolation technique to use",
        )

        group = param_parser.add_mutually_exclusive_group()
        group.add_argument(
            "-c",
            "--call_occup",
            type=str,
            default="",
            choices=possible_choices,
            help="Call occupation",
        )

        group.add_argument(
            "-m",
            "--mem_access",
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

    runner: Runner = Runner()
    config_data: ConfigData
    config_name: str

    # Check if the config subcommand is activated
    if args.command == "config":
        config_file: str = args.config
        config_data = runner.load_config(config_file=config_file)
        config_name = config_file.split("/")[-1].split(".")[0]

    elif args.command == "param":
        # 1. Load the base config file
        base_config_file: str = f"{Runner.CONFIG_DIR}base_config.json"
        config_data = runner.load_config(config_file=base_config_file)

        # 2. Use cli args to alter the base config
        # 2.1 Number of runs and their seeds
        config_data["nb_runs"] = args.nb_runs
        if args.seeds:
            if len(args.seeds) != config_data["nb_runs"]:
                raise IncorrectSeedsNumberException(
                    "Number of specified seeds is incorrect. The config file should"
                    " hold the same number of seeds and runs, if no seed are specified,"
                    " please use an empty list '[]'."
                )
            else:
                config_data["run_seeds"] = args.seeds

        # 2.2 Other parameters
        config_data["input_data"]["isolation_solution"] = args.isolation
        # TODO: Cursed
        parameters = ["nb_methods", "call_occup", "mem_access"]
        config_name = ""
        for parameter in parameters:
            if getattr(args, parameter):
                apply_fields_to_conf(
                    globals()[parameter][getattr(args, parameter)], config_data
                )
                config_name += (
                    f"{'_' if config_name else ''}{getattr(args, parameter)}_"
                    f"{parameter}"
                )

        if not config_name:
            config_name = "base_config"

    # 3. Format result directory name
    now: datetime.datetime = datetime.datetime.now()
    formatted_date: str = now.strftime("%Y-%m-%d_%H-%M-%S")
    base_dir_name: str = f"{Runner.RESULTS_DIR}{config_name}_{formatted_date}/"

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
        # 5.1 Generate binary
        seed: int = run_seeds[run_number]
        generation_data: GenerationData
        jit_elements_data: JITElementsData
        generation_data, jit_elements_data = runner.generate_binary(
            seed, config_data["input_data"]
        )
        # 5.2 Compile binary
        compilation_data: CompilationData = runner.compile_binary()
        # 5.3 Execute binary
        execution_data: ExecutionData = runner.execute_binary(
            start_address=compilation_data["dump_data"]["start_address"],
            ret_address=compilation_data["dump_data"]["ret_address"],
            rocket_input_data=config_data["input_data"]["rocket_input_data"],
        )
        # 5.4 Consolidate logs
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
    runner.store_gigue_data(gigue_data=full_data, data_file=f"{base_dir_name}data.json")
    return 0
