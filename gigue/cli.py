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
from typing import Type

from gigue.constants import BIN_DIR, CALLER_SAVED_REG
from gigue.exceptions import GeneratorException
from gigue.fixer.fixer_generator import FIXERTrampolineGenerator
from gigue.generator import Generator, TrampolineGenerator
from gigue.helpers import bytes_to_int
from gigue.rimi.rimi_generator import (
    RIMIFullTrampolineGenerator,
    RIMIShadowStackTrampolineGenerator,
)

logger = logging.getLogger("gigue")


class Parser(argparse.ArgumentParser):
    def __init__(self):
        super(Parser, self).__init__(description="Gigue, JIT code generator")
        self.add_parse_arguments()

    def add_parse_arguments(self):
        # Seed
        self.add_argument(
            "-s",
            "--seed",
            type=int,
            default=bytes_to_int(os.urandom(16)),
            help="Seed for the generation",
        )

        # Addresses
        # TODO: Should remove this one?
        self.add_argument(
            "-a",
            "--intaddr",
            type=int,
            default=0x0,
            help="Base address of the interpretation loop (the whole binary)",
        )
        self.add_argument(
            "-j",
            "--jitaddr",
            type=int,
            default=0x2000,
            help="Offset address of the JIT code",
        )

        # General
        self.add_argument(
            "-not",
            "--uses_trampolines",
            action="store_false",
            help="Uses trampoline for calls/returns (activated by default)",
        )
        self.add_argument(
            "-i",
            "--isolation",
            type=str,
            default="none",
            help=(
                "Isolation solution to protect the binary (none, fixer, rimiss,"
                " rimifull)"
            ),
        )
        # Method info
        self.add_argument(
            "-js",
            "--jitsize",
            type=int,
            default=1000,
            help="Size of the JIT binary in terms of instructions",
        )
        self.add_argument(
            "-n",
            "--nbmeth",
            type=int,
            default=100,
            help="Number of JIT code methods",
        )
        self.add_argument(
            "-vm",
            "--varmeth",
            type=float,
            default=0.2,
            help="Mean variation of method length variation",
        )
        self.add_argument(
            "-vs",
            "--stdevmeth",
            type=float,
            default=0.1,
            help="Mean standard deviation of method length variation",
        )
        self.add_argument(
            "--regs",
            action="append",
            default=CALLER_SAVED_REG,
            help="Registers that can be used freely by the generated code",
        )
        # Call info
        self.add_argument(
            "-cm",
            "--callmean",
            type=float,
            default=0.2,
            help="Mean call occupation",
        )
        self.add_argument(
            "-cs",
            "--callstdev",
            type=float,
            default=0.1,
            help="Standard deviation of call occupation",
        )
        self.add_argument(
            "-cdm",
            "--calldepthmean",
            type=int,
            default=2,
            help="Mean call depth (lambda parameter for a Poisson distribution)",
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
        # PICs info
        self.add_argument(
            "-r", "--picratio", type=float, default=0.2, help="PIC to method ratio"
        )
        self.add_argument(
            "--picmeancase", type=int, default=2, help="PIC mean number of cases"
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
            "-oi",
            "--outint",
            type=str,
            default=BIN_DIR + "int.bin",
            help="Name of the interpretation loop binary file",
        )
        self.add_argument(
            "-oj",
            "--outjit",
            type=str,
            default=BIN_DIR + "jit.bin",
            help="Name of the jit binary file",
        )
        self.add_argument(
            "-od",
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

    if not argv:
        parser.print_help()
        return 0

    if not os.path.exists(BIN_DIR):
        os.makedirs(BIN_DIR)

    logger.debug("🌳 Instanciating Generator.")

    gen_class: Type[Generator]
    if args.isolation == "none":
        if args.uses_trampolines:
            gen_class = TrampolineGenerator
        else:
            gen_class = Generator
    elif args.isolation == "fixer":
        assert (
            args.uses_trampolines
        ), "FIXER requires the use of trampolines (use the -T flag)."
        gen_class = FIXERTrampolineGenerator
    elif args.isolation == "rimiss":
        assert (
            args.uses_trampolines
        ), "RIMI (shadow stack) requires the use of trampolines (use the -t flag)."
        gen_class = RIMIShadowStackTrampolineGenerator
    elif args.isolation == "rimifull":
        assert (
            args.uses_trampolines
        ), "RIMI (full) requires the use of trampolines (use the -t flag)."
        gen_class = RIMIFullTrampolineGenerator
    try:
        gen = gen_class(
            # Addresses
            jit_start_address=args.jitaddr,
            interpreter_start_address=args.intaddr,
            # General
            jit_size=args.jitsize,
            jit_nb_methods=args.nbmeth,
            method_variation_mean=args.varmeth,
            method_variation_stdev=args.stdevmeth,
            call_depth_mean=args.calldepthmean,
            call_occupation_mean=args.callmean,
            call_occupation_stdev=args.callstdev,
            registers=args.regs,
            # Data
            data_reg=args.datareg,
            data_generation_strategy=args.datagen,
            data_size=args.datasize,
            # PICs
            pics_ratio=args.picratio,
            pics_mean_case_nb=args.picmeancase,
            pics_cmp_reg=args.piccmpreg,
            pics_hit_case_reg=args.pichitcasereg,
            # Files
            output_int_bin_file=args.outint,
            output_jit_bin_file=args.outjit,
            output_data_bin_file=args.outdata,
        )
    except GeneratorException as err:
        logging.exception(err)
        raise

    random.seed(args.seed)
    logger.debug(
        "🌱 Setting up seed as"
        f" {args.seed if isinstance(args.seed, int) else bytes_to_int(args.seed)}"
    )

    gen.main()

    return 0


if __name__ == "__main__":
    sys.exit(main())
