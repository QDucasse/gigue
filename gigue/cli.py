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
import random
import sys

from gigue.constants import BIN_DIR
from gigue.constants import CALLER_SAVED_REG
from gigue.exceptions import GeneratorException
from gigue.generator import Generator
from gigue.helpers import bytes_to_int

logger = logging.getLogger(__name__)


class Parser(argparse.ArgumentParser):
    def __init__(self):
        super(Parser, self).__init__(description="Gigue, JIT code generator")
        self.add_parse_arguments()

    def add_parse_arguments(self):
        # Seed
        self.add_argument(
            "-S",
            "--seed",
            type=int,
            default=bytes_to_int(os.urandom(16)),
            help="Start address of the interpretation loop",
        )
        # Addresses
        self.add_argument(
            "-I",
            "--intaddr",
            type=int,
            default=0,
            help="Start address of the interpretation loop",
        )
        self.add_argument(
            "-J",
            "--jitaddr",
            type=int,
            default=4096,  # 0x1000
            help="Start address of the JIT code",
        )

        # General
        self.add_argument(
            "-N",
            "--nbelt",
            type=int,
            default=200,
            help="Number of JIT code elements (methods/pics)",
        )
        self.add_argument(
            "--regs",
            type=list,
            default=CALLER_SAVED_REG,
            help="Registers that can be used freely by the generated code",
        )
        # Data info
        self.add_argument(
            "--datareg",
            type=int,
            default=31,
            help="Register that holds the address of the data section",
        )
        self.add_argument(
            "--datasize",
            type=int,
            default=8 * 200,
            help="Size of the data section",
        )
        self.add_argument(
            "--datagen",
            type=str,
            default="random",
            help="Data generation strategy",
        )
        # Method info
        self.add_argument(
            "-M",
            "--metmaxsize",
            type=int,
            default=50,
            help="Maximum size of a method (in nb of instructions)",
        )
        self.add_argument(
            "--maxcallnb",
            type=int,
            default=5,
            help="Maximum calls in a method (< msize/3 - 1)",
        )
        self.add_argument(
            "--maxcalldepth",
            type=int,
            default=5,
            help="Maximum call depth of a method (i.e. nested calls)",
        )
        # PICs info
        self.add_argument(
            "-R", "--picratio", type=float, default=0.2, help="PIC to method ratio"
        )
        self.add_argument(
            "-P", "--picmetmaxsize", type=int, default=25, help="PIC methods max size"
        )
        self.add_argument(
            "--picmaxcases", type=int, default=5, help="PIC max number of cases"
        )
        self.add_argument(
            "--piccmpreg",
            type=int,
            default=6,
            help="PIC register to store current comparison case",
        )
        self.add_argument(
            "--pichitcasereg",
            type=int,
            default=5,
            help="PIC register to store the case to be run",
        )
        # Output files
        self.add_argument(
            "-O",
            "--out",
            type=str,
            default=BIN_DIR + "out.bin",
            help="Name of the binary file",
        )
        self.add_argument(
            "--outdata",
            type=str,
            default=BIN_DIR + "data.bin",
            help="Name of the binary data file",
        )

    def parse(self, args):
        return self.parse_args(args)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = Parser()
    args = parser.parse(argv)

    if not os.path.exists(BIN_DIR):
        os.makedirs(BIN_DIR)

    logger.info("🌳 Instanciating Generator.")

    try:
        gen = Generator(
            # Addresses
            jit_start_address=args.jitaddr,
            interpreter_start_address=args.intaddr,
            # General
            registers=args.regs,
            jit_elements_nb=args.nbelt,
            # Data
            data_reg=args.datareg,
            data_generation_strategy=args.datagen,
            data_size=args.datasize,
            # Methods
            method_max_size=args.metmaxsize,
            max_call_depth=args.maxcalldepth,
            max_call_nb=args.maxcallnb,
            # PICs
            pics_ratio=args.picratio,
            pics_method_max_size=args.picmetmaxsize,
            pics_max_cases=args.picmaxcases,
            pics_cmp_reg=args.piccmpreg,
            pics_hit_case_reg=args.pichitcasereg,
            # Files
            output_bin_file=args.out,
            output_data_bin_file=args.outdata,
        )
    except GeneratorException as err:
        logging.exception(err)
        raise

    random.seed(args.seed)
    logger.info(
        "🌱 Setting up seed as"
        f" {args.seed if isinstance(args.seed, int) else bytes_to_int(args.seed)}"
    )

    gen.main()

    return 0
