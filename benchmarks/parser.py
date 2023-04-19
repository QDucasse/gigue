import logging
import re
from typing import Tuple

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

    def parse_dumps(self, dump_file, log_file) -> None:
        try:
            start_address, end_address = self.extract_addresses_from_dump(dump_file)
            self.extract_cycles_from_rocket_log(start_address, end_address, log_file)
        except (
            MissingAddressException,
            MissingCycleException,
            EnvironmentError,
        ) as err:
            logger.error(err)
            raise

        # TODO (elsewhere): Extract info from generation:
        #  - All info + seed

        # TODO (here): Extract info from dump:
        #  - Binary size
        #  - Start address
        #  - End address
        #  - Data address

        # TODO (here): Extract info from dump:
        #  - Binary size
        #  - Start address
        #  - End address
        #  - Data address

    # Dump extraction
    # \________________

    @staticmethod
    def extract_addresses_from_dump(dump_file: str) -> Tuple[int, int]:
        # 0000000080002a24 <gigue_start>:
        # 00000000800102e4 <gigue_end>:
        start_address: int = -1
        end_address: int = -1
        try:
            with open(dump_file) as dump:
                for line in dump:
                    # Only keep sections
                    if ":" in line:
                        # Check for gigue_start
                        if "<gigue_start>" in line:
                            start_address = int(line.split(" ")[0], 16)
                        # Check for gigue_end and take the address right before
                        if "<gigue_end>" in line:
                            end_address = int(line.split(" ")[0], 16) - 4
            if start_address == -1:
                raise MissingAddressException(
                    "Start address was not found in the dump."
                )
            if end_address == -1:
                raise MissingAddressException("End address was not found in the dump.")
        except EnvironmentError as err:
            logger.error(err)
            raise
        return start_address, end_address

    # Rocket log extraction
    # \______________________

    @staticmethod
    def extract_cycles_from_rocket_log(
        start_address: int, end_address: int, rocket_log_file: str
    ) -> Tuple[int, int]:
        # C0:    1114705 [1]
        # pc=[0000000080002a24] W[r 2=0000000080030c28][1]
        # R[r 2=0000000080030c80] R[r 0=0000000000000000]
        # inst=[fa810113] addi    sp, sp, -88
        start_cycle: int = -1
        end_cycle: int = -1
        try:
            with open(rocket_log_file) as rocket_log:
                for line in rocket_log:
                    match = re.search(LogParser.ROCKET_PC_CYCLE_REGEX, line)
                    if match:
                        if int(match.group(2), 16) == start_address:
                            start_cycle = int(match.group(1))
                        if int(match.group(2), 16) == end_address:
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
        return start_cycle, end_cycle
