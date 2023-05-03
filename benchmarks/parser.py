import logging
import re
from typing import Tuple

from benchmarks.data import DumpData, EmulationData

logger = logging.getLogger(__name__)

# Parsing exceptions
# \___________________


class ParserException(Exception):
    pass


class MissingAddressException(ParserException):
    pass


class MissingCycleException(ParserException):
    pass


class LogParser:
    # Extracts the cycle in the first group and pc in the second
    #                               vvvvv            vvvvv
    ROCKET_PC_CYCLE_REGEX: str = r"C0:\s*(\d+) \[1\] pc=\[(.*?)\]"

    # Main methods
    # \____________
    # TODO: Split in two
    def parse_dump(self, dump_file: str) -> DumpData:
        # Correctness flag
        dump_ok: int = 0
        # Default values
        start_address: int = 0
        end_address: int = 0
        ret_address: int = 0
        try:
            # Extract info
            start_address, ret_address, end_address = self.extract_from_dump(dump_file)
            dump_ok = 1
        except (
            MissingAddressException,
            EnvironmentError,
        ) as err:
            # If missing info in the dump trigger flag
            logger.error(err)
            dump_ok = 0
        # Format output data
        dump_info: DumpData = {
            "dump_ok": dump_ok,
            "start_address": start_address,
            "end_address": end_address,
            "ret_address": ret_address,
            "bin_size": end_address - start_address,
        }
        return dump_info

    def parse_rocket_log(
        self, log_file: str, start_address: int, ret_address: int
    ) -> EmulationData:
        # Correctness flag
        emulation_ok: int = 0
        # Default values
        seed: int = 0
        start_cycle: int = 0
        end_cycle: int = 0
        try:
            # Extract info
            seed, start_cycle, end_cycle = self.extract_from_rocket_log(
                start_address=start_address,
                ret_address=ret_address,
                rocket_log_file=log_file,
            )
            emulation_ok = 1
        except (
            MissingCycleException,
            EnvironmentError,
        ) as err:
            # If missing info in the logs trigger flag
            logger.error(err)
            emulation_ok = 0
        # Format output data
        emulation_info: EmulationData = {
            "emulation_ok": emulation_ok,
            "verilator_seed": seed,
            "start_cycle": start_cycle,
            "end_cycle": end_cycle,
            "nb_cycles": end_cycle - start_cycle,
        }
        return emulation_info

    # Dump extraction
    # \________________

    @staticmethod
    def extract_from_dump(dump_file: str) -> Tuple[int, int, int]:
        # 0000000080002a24 <gigue_start>:
        # 00000000800102e4 <gigue_end>:
        start_regex = r"(\w*) <gigue_start>:"
        end_regex = r"(\w*) <gigue_end>:"
        start_address: int = -1
        end_address: int = -1
        ret_address: int = -1
        try:
            with open(dump_file) as dump:
                # Flag to get the interpreter ret address
                in_gigue_bin = False
                for line in dump:
                    # Check start
                    match_start = re.search(start_regex, line)
                    if match_start:
                        start_address = int(match_start.group(1), 16)
                        in_gigue_bin = True
                    # Check end and use address right before
                    match_end = re.search(end_regex, line)
                    if match_end:
                        end_address = int(match_end.group(1), 16) - 4
                        in_gigue_bin = False
                    if in_gigue_bin and "ret" in line:
                        ret_address = int(line.split(":")[0], 16)
                        in_gigue_bin = False
            if start_address == -1:
                raise MissingAddressException(
                    "Start address was not found in the dump."
                )
            if end_address == -1:
                raise MissingAddressException("End address was not found in the dump.")
            if ret_address == -1:
                raise MissingAddressException("Ret address was not found in the dump.")
        except EnvironmentError as err:
            logger.error(err)
            raise
        # TODO: Use a data structure
        return start_address, ret_address, end_address

    # Rocket log extraction
    # \______________________

    @staticmethod
    def extract_from_rocket_log(
        start_address: int, ret_address: int, rocket_log_file: str
    ) -> Tuple[int, int, int]:
        # using random seed 1681861037
        # ...
        # C0:    1114705 [1]
        # pc=[0000000080002a24] W[r 2=0000000080030c28][1]
        # R[r 2=0000000080030c80] R[r 0=0000000000000000]
        # inst=[fa810113] addi    sp, sp, -88
        # ...
        seed: int = -1
        start_cycle: int = -1
        end_cycle: int = -1
        try:
            with open(rocket_log_file) as rocket_log:
                for i, line in enumerate(rocket_log):
                    # Extract the seed on the first line
                    if i == 0:
                        seed = int(line.split(" ")[-1])
                    # Extract both the PC and cycle info
                    match = re.search(LogParser.ROCKET_PC_CYCLE_REGEX, line)
                    if match:
                        if int(match.group(2), 16) == start_address:
                            start_cycle = int(match.group(1))
                        if int(match.group(2), 16) == ret_address:
                            end_cycle = int(match.group(1))
            if start_cycle == -1:
                raise MissingCycleException(
                    "Start cycle was not found (start address never met) in the rocket"
                    " logs."
                )
            if end_cycle == -1:
                raise MissingCycleException(
                    "End cycle was not found (end address never met) in the rocket"
                    " logs."
                )
        except EnvironmentError as err:
            logger.error(err)
            raise
        # TODO: Use a data structure
        return seed, start_cycle, end_cycle


if __name__ == "__main__":
    parser = LogParser()
    start_address, ret_address, _ = parser.extract_from_dump("bin/out.dump")
    _, start_cycle, end_cycle = parser.extract_from_rocket_log(
        start_address=start_address,
        ret_address=ret_address,
        rocket_log_file="bin/out.rocket",
    )
    print(
        f"Start address: {hex(start_address)}\n"
        f"Ret address:   {hex(ret_address)}\n"
        f"Nb cycles:     {end_cycle - start_cycle}"
    )
