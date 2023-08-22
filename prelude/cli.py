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
import logging
import os
import shutil
import subprocess
import sys
from typing import List, Optional

from gigue.constants import BIN_DIR
from gigue.dataminer import Dataminer
from gigue.rimi.rimi_constants import RIMI_INSTRUCTIONS_INFO
from prelude.exceptions import MissingHelperException
from prelude.proc_helper import GNUHelper, Helper, RocketHelper
from prelude.tutorials import RIMI_TUTORIAL

logger = logging.getLogger("prelude")
logger.setLevel(logging.INFO)


class Parser(argparse.ArgumentParser):
    def __init__(self):
        super(Parser, self).__init__(description="Prelude, binary tests and helpers")
        self.add_parse_arguments()

    def add_parse_arguments(self):
        subparsers = self.add_subparsers(
            dest="command", parser_class=argparse.ArgumentParser
        )

        helper_parser = subparsers.add_parser("helper")
        helper_parser.add_argument(
            "helper",
            type=str,
            default="",
            help=(
                "Print helper infos for known tools and targets, e.g. rocket, cva6,"
                " gnu, ..."
            ),
        )

        instr_parser = subparsers.add_parser("instr")
        instr_parser.add_argument(
            "instr",
            type=str,
            default="",
            help=(
                "Instruction to generate a unit test of, e.g. lb1, lh1, ... and special"
                " cases 'all' to generate all binary unit tests separately or 'concat'"
                " to generate concatenated"
            ),
        )

        instr_parser.add_argument(
            "-t",
            "--template",
            type=str,
            default="unit",
            help=(
                "Assembly template to use for the binary (found in"
                " resources/common/templates), e.g. unit, unitrimi"
            ),
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

    if args.command == "helper":
        printer: Helper
        if args.helper == "rocket":
            logger.info("Displaying Rocket help...")
            printer = RocketHelper()
        elif args.helper == "gnu":
            logger.info("Displaying GNU toolchain help...")
            printer = GNUHelper()
        else:
            msg = f"No helper has been defined for {args.helper}."
            logger.error(msg)
            raise MissingHelperException(msg)

        help = printer.get_output(
            list(RIMI_INSTRUCTIONS_INFO.keys()), RIMI_INSTRUCTIONS_INFO
        )
        logger.info(f"\n{help}")

    if args.command == "instr":
        miner = Dataminer()
        with open(BIN_DIR + "data.bin", "wb") as file:
            file.write(miner.generate_data("iterative64", 100))
        with open(BIN_DIR + "ss.bin", "wb") as file:
            file.write(miner.generate_data("zeroes", 10))

        # Test specific variable 'all'
        all_instrs = list(RIMI_INSTRUCTIONS_INFO.keys())
        if args.instr == all:
            instr_names = all_instrs
        else:
            # Check existence of the requested instruction
            if args.instr not in all_instrs:
                msg = (
                    f"Instruction {args.instr} not found in the instruction"
                    " information."
                )
                logger.error(msg)
                raise KeyError(msg)
            instr_names = [args.instr]

        for instr_name in instr_names:
            with open("bin/unit.bin", "wb") as file:
                bytes_instr = RIMI_TUTORIAL.example_binary_for(instr_name)
                file.write(bytes_instr)
            subprocess.run(
                ["make", "unitdump", f"TEMPLATE={args.template}"],
                timeout=10,
                check=True,
            )
            # Copy the resulting elf
            base_dir = f"{BIN_DIR}/unit"
            if not os.path.exists(base_dir):
                os.makedirs(base_dir)
            shutil.copy(
                src=f"{BIN_DIR}/unit.elf",
                dst=f"{BIN_DIR}/unit/{args.instr}.elf",
            )

    return 0
