import logging
import re
from abc import abstractmethod
from collections import Counter
from typing import List, Mapping

from gigue.constants import InstructionInfo
from toccata.data import (
    DumpData,
    DumpParsingData,
    EmulationData,
    InstrClassData,
    InstrTypeData,
    LogParsingData,
    TracingData,
    default_instr_class_data,
    default_instr_type_data,
)

logger = logging.getLogger(__name__)

# Parsing exceptions
# \___________________


class ParserException(Exception):
    pass


class MissingAddressException(ParserException):
    pass


class MissingCycleException(ParserException):
    pass


class DumpParser:
    # Info filling methods
    # \_____________________

    def parse_dump(self, dump_file: str) -> DumpData:
        # Correctness flag
        dump_ok: int = 0
        # Default values
        start_address: int = 0
        end_address: int = 0
        try:
            # Extract info
            dump_parsed_data: DumpParsingData = self.extract_from_dump(dump_file)
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
            "start_address": dump_parsed_data["start_address"],
            "end_address": dump_parsed_data["end_address"],
            "ret_address": dump_parsed_data["ret_address"],
            "bin_size": end_address - start_address,
        }
        return dump_info

    @staticmethod
    def extract_from_dump(dump_file: str) -> DumpParsingData:
        # 0000000080002a24 <gigue_start>:
        # 00000000800102e4 <gigue_end>:
        start_regex = r"(\w*) <gigue_int_start>:"
        end_regex = r"(\w*) <main>:"
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
        dump_parsing_data: DumpParsingData = {
            "start_address": start_address,
            "ret_address": ret_address,
            "end_address": end_address,
        }
        return dump_parsing_data


class LogParser:
    def parse_core_log(
        self,
        log_file: str,
        start_address: int,
        ret_address: int,
        instructions_info: Mapping[str, InstructionInfo],
        verbose: bool = False,
    ) -> EmulationData:
        # Correctness flag
        emulation_ok: int = 0
        tracing_ok: int = 0
        # Tracing data
        instrs_class: InstrClassData = default_instr_class_data()
        instrs_type: InstrTypeData = default_instr_type_data()
        try:
            # Extract info
            rocket_parsed_data: LogParsingData = self.extract_from_core_log(
                start_address=start_address,
                ret_address=ret_address,
                core_log_file=log_file,
            )
            emulation_ok = 1
        except (
            MissingCycleException,
            EnvironmentError,
        ) as err:
            # If missing info in the logs trigger flag
            logger.error(err)
            emulation_ok = 0

        if emulation_ok == 1:
            executed_instructions: List[str] = rocket_parsed_data["executed_instrs"]
            # Instr type
            executed_instrs_type: List[str] = [
                instructions_info[instr].instr_type for instr in executed_instructions
            ]

            instrs_type_counter = Counter(executed_instrs_type)
            for key, val in instrs_type_counter.items():
                try:
                    instrs_type[key] = val  # type: ignore
                except KeyError as err:
                    logger.exception(err)
                    logger.exception(
                        "This type of instruction is not defined in the available ones,"
                        " see InstrTypeData."
                    )
                    raise

            # Instr class
            executed_instrs_class: List[str] = [
                instructions_info[instr].instr_class for instr in executed_instructions
            ]

            instrs_class_counter = Counter(executed_instrs_class)
            for key, val in instrs_class_counter.items():
                try:
                    instrs_class[key] = val  # type: ignore
                except KeyError as err:
                    logger.exception(err)
                    logger.exception(
                        "This class of instruction is not defined in the available"
                        " ones, see InstrClassData."
                    )
                    raise

            # Tracing went ok
            tracing_ok = 1

        # If the emulation wasnt ok, simply pass the default values
        tracing_info: TracingData = {
            "tracing_ok": tracing_ok,
            "instrs_nb": len(executed_instructions),
            "instrs_type": instrs_type,
            "instrs_class": instrs_class,
        }

        if verbose:
            print("Executed instructions:")
            print(Counter(executed_instructions))
        # Format output data
        emulation_info: EmulationData = {
            "emulation_ok": emulation_ok,
            "verilator_seed": rocket_parsed_data["sim_seed"],
            "start_cycle": rocket_parsed_data["start_cycle"],
            "end_cycle": rocket_parsed_data["end_cycle"],
            "nb_cycles": rocket_parsed_data["end_cycle"]
            - rocket_parsed_data["start_cycle"],
            "tracing_data": tracing_info,
        }
        return emulation_info

    @staticmethod
    @abstractmethod
    def extract_from_core_log(
        start_address: int, ret_address: int, core_log_file: str
    ) -> LogParsingData:
        pass


class RocketLogParser(LogParser):
    # Core log extraction
    # \______________________

    @staticmethod
    def extract_from_core_log(
        start_address: int, ret_address: int, core_log_file: str
    ) -> LogParsingData:
        # using random seed 1681861037
        # ...
        # C0:    1114705 [1]
        # pc=[0000000080002a24] W[r 2=0000000080030c28][1]
        # R[r 2=0000000080030c80] R[r 0=0000000000000000]
        # inst=[fa810113] addi    sp, sp, -88
        # ...
        # Extracts the cycle in the first group, the pc in the second and instr
        #            vvvv             vvvvvvvvv                     vvvvv
        ROCKET_PC_CYCLE_INSTR_REGEX: str = (
            r"C0:\s*(\d+) \[1\] pc=\[([0-9a-fA-F]+)\].*inst=\[.*?\] (\w*)"
        )
        seed: int = -1
        start_cycle: int = -1
        end_cycle: int = -1
        executed_instructions: List[str] = []
        try:
            with open(core_log_file) as core_log:
                in_gigue = False
                for i, line in enumerate(core_log):
                    # Extract the seed on the first line
                    if i == 0:
                        seed = int(line.split(" ")[-1])
                    # Extract both the PC and cycle info
                    match = re.search(ROCKET_PC_CYCLE_INSTR_REGEX, line)
                    if match:
                        if int(match.group(2), 16) == start_address:
                            start_cycle = int(match.group(1))
                            in_gigue = True
                        if int(match.group(2), 16) == ret_address:
                            end_cycle = int(match.group(1))
                            in_gigue = False
                            break
                        if in_gigue:
                            executed_instructions.append(match.group(3))
            if start_cycle == -1:
                raise MissingCycleException(
                    "Start cycle was not found (start address never met) in the core"
                    " logs."
                )
            if end_cycle == -1:
                raise MissingCycleException(
                    "End cycle was not found (end address never met) in the core logs."
                )
        except EnvironmentError as err:
            logger.error(err)
            raise
        rocket_parsed_data: LogParsingData = {
            "sim_seed": seed,
            "start_cycle": start_cycle,
            "end_cycle": end_cycle,
            "executed_instrs": executed_instructions,
        }
        return rocket_parsed_data


class CVA6LogParser(LogParser):
    # Core log extraction
    # \______________________

    @staticmethod
    def extract_from_core_log(
        start_address: int, ret_address: int, core_log_file: str
    ) -> LogParsingData:
        # This emulator compiled with JTAG Remote
        # Bitbang client. To enable, use +jtag_rbb_enable=1.
        # Listening on port 35955
        # No explicit VCD file name supplied, using RTL defaults.
        # bin/out.elf *** SUCCESS *** (tohost = 0) after 67271 cycles
        # *** [rvf_tracer] WARNING: No valid address of 'tohost'
        # (tohost == 0x00000000000000),
        # termination possible only by timeout or Ctrl-C!
        # CPU time used: 20501.60 ms
        # Wall clock time passed: 20522.29 ms
        #  265 0x10000 M (0x00100413) li      s0, 1
        #  270 0x10004 M (0x01f41413) slli    s0, s0, 31
        #  ...

        # Extracts the cycle in the first group, the pc in the second and instr
        #                                      vvvvv vvvvvvvvvvvvvvvv     vvvvv
        CVA6_PC_CYCLE_INSTR_REGEX: str = r"^\s*(\d+) (0x[0-9a-fA-F]+).*\) (\w*)"
        start_cycle: int = -1
        end_cycle: int = -1
        executed_instructions: List[str] = []
        try:
            with open(core_log_file) as core_log:
                in_gigue = False
                for i, line in enumerate(core_log):
                    # Extract both the PC and cycle info
                    match = re.search(CVA6_PC_CYCLE_INSTR_REGEX, line)
                    if match:
                        if int(match.group(2), 16) == start_address:
                            start_cycle = int(match.group(1))
                            in_gigue = True
                        if int(match.group(2), 16) == ret_address:
                            end_cycle = int(match.group(1))
                            in_gigue = False
                            break
                        if in_gigue:
                            executed_instructions.append(match.group(3))
            if start_cycle == -1:
                raise MissingCycleException(
                    "Start cycle was not found (start address never met) in the core"
                    " logs."
                )
            if end_cycle == -1:
                raise MissingCycleException(
                    "End cycle was not found (end address never met) in the core logs."
                )
        except EnvironmentError as err:
            logger.error(err)
            raise
        # Note: CVA6 does not have this seed input
        cva6_parsed_data: LogParsingData = {
            "sim_seed": 0,
            "start_cycle": start_cycle,
            "end_cycle": end_cycle,
            "executed_instrs": executed_instructions,
        }
        return cva6_parsed_data


if __name__ == "__main__":
    # Utility to parse the current dumps
    from gigue.constants import INSTRUCTIONS_INFO

    instructions_info: Mapping[str, InstructionInfo] = INSTRUCTIONS_INFO

    cva6_parser = CVA6LogParser()
    dump_parser = DumpParser()
    dump_data: DumpData = dump_parser.parse_dump(dump_file="bin/out.dump")
    cva6_emulation_data: EmulationData = cva6_parser.parse_core_log(
        start_address=dump_data["start_address"],
        ret_address=dump_data["ret_address"],
        log_file="bin/cva6.log",
        instructions_info=instructions_info,
        verbose=True,
    )
    print(
        f"Start address: {hex(dump_data['start_address'])}\n"
        f"Ret address:   {hex(dump_data['ret_address'])}\n"
        f"Nb cycles:     {cva6_emulation_data['nb_cycles']}\n"
        f"Instrs type:   {cva6_emulation_data['tracing_data']['instrs_type']}\n"
        f"Instrs class:  {cva6_emulation_data['tracing_data']['instrs_class']}"
    )

    rocket_parser = RocketLogParser()
    rocket_emulation_data: EmulationData = rocket_parser.parse_core_log(
        start_address=dump_data["start_address"],
        ret_address=dump_data["ret_address"],
        log_file="bin/rocket.log",
        instructions_info=instructions_info,
        verbose=True,
    )
    print(
        f"Start address: {hex(dump_data['start_address'])}\n"
        f"Ret address:   {hex(dump_data['ret_address'])}\n"
        f"Nb cycles:     {rocket_emulation_data['nb_cycles']}\n"
        f"Instrs type:   {rocket_emulation_data['tracing_data']['instrs_type']}\n"
        f"Instrs class:  {rocket_emulation_data['tracing_data']['instrs_class']}"
    )
