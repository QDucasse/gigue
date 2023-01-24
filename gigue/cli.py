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
import os
import sys

from gigue.constants import BIN_DIR
from gigue.constants import CALLER_SAVED_REG
from gigue.generator import Generator
from gigue.helpers import ObjDict


class Parser(argparse.ArgumentParser):
    def __init__(self):
        super(Parser, self).__init__(description="Gigue, JIT code generator")
        self.add_parse_arguments()

    def add_parse_arguments(self):
        # Addresses
        self.add_argument(
            "--jitaddr", type=int, default=0xF000, help="Start address of the JIT code"
        )
        self.add_argument(
            "--intaddr",
            type=int,
            default=0x0000,
            help="Start address of the interpretation loop",
        )
        # General
        self.add_argument(
            "--jitnb",
            type=int,
            default=200,
            help="Number of JIT code elements (methods/pics)",
        )
        self.add_argument(
            "--regs",
            type=int,
            default=CALLER_SAVED_REG,
            help="Registers that can be used freely by the generated code",
        )
        # Method info
        self.add_argument(
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
            "--picratio", type=int, default=0.2, help="PIC to method ratio"
        )
        self.add_argument(
            "--picmetmaxsize", type=int, default=20, help="PIC methods max size"
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
            "--outjitbin",
            type=str,
            default=BIN_DIR + "jit.bin",
            help="Name of the binary file for the JIT code",
        )
        self.add_argument(
            "--outintbin",
            type=str,
            default=BIN_DIR + "interpret.bin",
            help="Name of the binary file for the interpretation loop",
        )

    def parse(self, args):
        return self.parse_args(args)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = Parser()
    parsed_args = parser.parse(argv)
    args = ObjDict(parsed_args.__dict__)

    if not os.path.exists(BIN_DIR):
        os.makedirs(BIN_DIR)

    g = Generator(
        # Addresses
        jit_start_address=args.jitaddr,
        interpreter_start_address=args.intaddr,
        # General
        registers=args.regs,
        jit_elements_nb=args.jitnb,
        pics_ratio=args.picratio,
        max_call_depth=args.maxcalldepth,
        max_call_nb=args.maxcallnb,
        # Methods
        method_max_size=args.metmaxsize,
        # PICs
        pics_method_max_size=args.picmetmaxsize,
        pics_max_cases=args.picmaxcases,
        pics_cmp_reg=args.piccmpreg,
        pics_hit_case_reg=args.pichitcasereg,
        # Files
        output_jit_file=args.outjitbin,
        output_interpret_file=args.outintbin,
    )
    g.main()
    return 0
