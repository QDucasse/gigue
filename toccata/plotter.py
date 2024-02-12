from __future__ import annotations

import json
import math
import os
import re
from typing import TYPE_CHECKING, Callable, List, Optional

from gigue.helpers import mean
from toccata.data import (
    CallApplicationClassData,
    EmulationData,
    FullData,
    MemoryApplicationClassData,
    OverheadCallComparisonData,
    OverheadMemoryComparisonData,
    RunData,
    TracingData,
)

if TYPE_CHECKING:
    from matplotlib.axes import Axes


class Plotter:
    # Config define the different application classes
    LOCKED_RESULTS_PATH = "benchmarks/results/locked/"

    PLOT_COLORS = {
        "low": 0.2,
        "medium": 0.5,
        "high": 0.9,
    }

    # Template method to process all runs of an application class
    # \_________________________________________________________________

    def extract_from_full_data(self, full_data: FullData, extraction_method: Callable):
        extracted_class_info: List[float] = []
        nb_runs: int = full_data["config_data"]["nb_runs"]
        for i in range(nb_runs):
            run_data = full_data["run_data"][i]
            extracted_app_info = extraction_method(run_data)
            extracted_class_info.append(extracted_app_info)
        return extracted_class_info

    # Metric 1: Number of methods (for a fixed bin size)
    # \___________________________________________________

    def extract_run_nb_methods(self, run_data: RunData):
        nb_method: int = run_data["generation_data"]["nb_methods"]
        return nb_method

    def extract_nb_methods(self, full_data: FullData):
        return self.extract_from_full_data(
            full_data=full_data, extraction_method=self.extract_run_nb_methods
        )

    def extract_run_mean_method_size(self, run_data: RunData):
        mean_method_size: float = run_data["generation_data"]["mean_method_size"]
        return mean_method_size

    def extract_mean_method_sizes(self, full_data: FullData):
        return self.extract_from_full_data(
            full_data=full_data, extraction_method=self.extract_run_mean_method_size
        )

    # Metric 2: Call Occupation (% of body size dedicated to calls)
    # \_______________________________________________________________

    def extract_run_call_density(self, run_data: RunData):
        call_occupation: float = (
            run_data["generation_data"]["mean_method_call_occupation"] * 100
        )
        return call_occupation

    def extract_call_occupations(self, full_data: FullData):
        return self.extract_from_full_data(
            full_data=full_data, extraction_method=self.extract_run_call_density
        )

    # Mem accesses presence (aka how filled are the methods with memory accesses)
    # \______________________________________________________________________________

    def extract_mem_access(self, run_data: RunData):
        tracing_data: TracingData = run_data["execution_data"]["emulation_data"][
            "tracing_data"
        ]
        instrs_nb: int = tracing_data["instrs_nb"]
        mem_instrs_nb: int = tracing_data["instrs_class"]["memory"]
        mem_access: float = mem_instrs_nb / instrs_nb * 100 if instrs_nb != 0 else 0
        return mem_access

    def extract_mem_accesses(self, full_data: FullData):
        return self.extract_from_full_data(
            full_data=full_data, extraction_method=self.extract_mem_access
        )

    # Extract Cycles
    # \________________

    def extract_cycle(self, run_data: RunData):
        cycles_nb: int = run_data["execution_data"]["emulation_data"]["nb_cycles"]
        return cycles_nb

    def extract_cycles(self, full_data: FullData):
        return self.extract_from_full_data(
            full_data=full_data, extraction_method=self.extract_cycle
        )

    # Extract Cycles per instruction
    # \__________________________________

    def extract_cycle_per_instruction(self, run_data: RunData):
        emulation_data: EmulationData = run_data["execution_data"]["emulation_data"]
        instrs_nb: int = emulation_data["tracing_data"]["instrs_nb"]
        cycles_nb: int = emulation_data["nb_cycles"]
        cpi: float = cycles_nb / instrs_nb if instrs_nb != 0 else 0
        return cpi

    def extract_cpis(self, full_data: FullData):
        return self.extract_from_full_data(
            full_data=full_data, extraction_method=self.extract_cycle_per_instruction
        )

    # Extraction from call applications
    # \____________________________________

    def process_call_application_classes(
        self,
        isolation_types: List[str] = [""],
        experiments_path: Optional[str] = None,
        store_plot_data: bool = False,
    ) -> List[CallApplicationClassData]:
        if experiments_path is None:
            experiments_path = Plotter.LOCKED_RESULTS_PATH
        if len(isolation_types) == 0:
            isolation_types.append("")
        application_classes_data: List[CallApplicationClassData] = []
        call_apps_path: str = experiments_path + "calls/"
        for call_app_path in os.listdir(call_apps_path):
            with open(f"{call_apps_path}/{call_app_path}/data.json", "r") as data:
                full_data: FullData = json.load(data)
                # Extract method nb
                nb_methods: List[int] = self.extract_run_nb_methods(
                    full_data["run_data"][0]
                )
                mean_method_sizes: List[float] = self.extract_mean_method_sizes(
                    full_data
                )
                # Extract call density
                call_occupations: List[float] = self.extract_call_occupations(full_data)
                # Extract cycle nb
                nb_cycles: List[int] = self.extract_cycles(full_data)
                # Extract CPI
                cpis: List[float] = self.extract_cpis(full_data)
                # Extract qualifiers
                config_name = full_data["config_data"]["config_name"]
                pattern = re.escape(config_name) + r"_(\w+)_nbmethods_(\w+)_calloccup"
                match = re.search(pattern, call_app_path)
                if match is not None:
                    nb_methods_qualif = match.group(1)
                    call_occupations_qualif = match.group(2)
                else:
                    raise Exception("Regex empty.")
                call_application_class_data: CallApplicationClassData = {
                    "name": str(call_app_path),
                    "nb_methods_qualif": nb_methods_qualif,
                    "call_occupations_qualif": call_occupations_qualif,
                    "isolation": full_data["config_data"]["input_data"][
                        "isolation_solution"
                    ],
                    "nb_methods": nb_methods,
                    "mean_method_sizes": mean_method_sizes,
                    "call_occupations": call_occupations,
                    "nb_cycles": nb_cycles,
                    "cpis": cpis,
                }
                application_classes_data.append(call_application_class_data)
        if store_plot_data:
            with open(f"{experiments_path}/calls_plot_data.json", "w") as outfile:
                json.dump(
                    application_classes_data, outfile, indent=2, separators=(",", ": ")
                )
        return application_classes_data

    # Extraction from mem applications
    # \____________________________________

    def process_mem_application_classes(
        self,
        isolation_types: List[str] = [""],
        experiments_path: Optional[str] = None,
        store_plot_data: bool = False,
    ) -> List[MemoryApplicationClassData]:
        if experiments_path is None:
            experiments_path = Plotter.LOCKED_RESULTS_PATH
        if len(isolation_types) == 0:
            isolation_types.append("")
        application_classes_data: List[MemoryApplicationClassData] = []
        mem_apps_path: str = experiments_path + "memory/"
        for mem_app_path in os.listdir(mem_apps_path):
            with open(f"{mem_apps_path}/{mem_app_path}/data.json", "r") as data:
                full_data: FullData = json.load(data)
                # Extract method nb
                nb_methods: List[int] = self.extract_nb_methods(full_data)
                mean_method_sizes: List[float] = self.extract_mean_method_sizes(
                    full_data
                )
                # Extract mem density
                mem_accesses: List[float] = self.extract_mem_accesses(full_data)
                # Extract cycle nb
                nb_cycles: List[int] = self.extract_cycles(full_data)
                # Extract CPI
                cpis: List[float] = self.extract_cpis(full_data)
                # Extract qualifiers
                config_name = full_data["config_data"]["config_name"]
                pattern = re.escape(config_name) + r"_(\w+)_nbmethods_(\w+)_memaccess"
                match = re.search(pattern, mem_app_path)
                if match is not None:
                    nb_methods_qualif = match.group(1)
                    mem_accesses_qualif = match.group(2)
                else:
                    raise Exception("Regex empty.")
                mem_application_class_data: MemoryApplicationClassData = {
                    "name": str(mem_app_path),
                    "nb_methods_qualif": nb_methods_qualif,
                    "mem_accesses_qualif": mem_accesses_qualif,
                    "isolation": full_data["config_data"]["input_data"][
                        "isolation_solution"
                    ],
                    "nb_methods": nb_methods,
                    "mean_method_sizes": mean_method_sizes,
                    "mem_accesses": mem_accesses,
                    "nb_cycles": nb_cycles,
                    "cpis": cpis,
                }
                application_classes_data.append(mem_application_class_data)
        if store_plot_data:
            with open(f"{experiments_path}/mem_plot_data.json", "w") as outfile:
                json.dump(
                    application_classes_data, outfile, indent=2, separators=(",", ": ")
                )
        return application_classes_data

    # Plot Calls Application Classes
    # \__________________________________

    def plot_call_application_classes(
        self, ax, application_classes_data: List[CallApplicationClassData]
    ):
        for app_data in application_classes_data:
            ax.scatter(
                # [app_data["nb_methods"]] * len(app_data["call_occupations"]),
                [size * 4 for size in app_data["mean_method_sizes"]],
                app_data["call_occupations"],
                color="green",
                alpha=0.5,
            )

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_ylim(0, 7)
        ax.tick_params(axis="x", labelsize=16)
        ax.tick_params(axis="y", labelsize=16)
        ax.set_xlabel("Mean method size (bytes)", fontsize=20)
        ax.set_ylabel("Call occupation (%)", fontsize=20)
        ax.set_title("Call occupation application classes", fontsize=20, pad=30)

    # Plot Memory Application Classes
    # \__________________________________

    def plot_mem_application_classes(
        self, ax: Axes, application_classes_data: List[MemoryApplicationClassData]
    ):
        for app_data in application_classes_data:
            ax.scatter(
                # app_data["nb_methods"],
                [size * 4 for size in app_data["mean_method_sizes"]],
                app_data["mem_accesses"],
                color="blue",
                alpha=0.5,
                # Plotter.PLOT_COLORS[app_data["mem_accesses_qualif"]]
            )

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_ylim(0, 50)
        ax.tick_params(axis="x", labelsize=16)
        ax.tick_params(axis="y", labelsize=16)
        ax.set_xlabel("Mean method size (bytes)", fontsize=20)
        ax.set_ylabel("Memory accesses (%)", fontsize=20)
        ax.set_title("Memory accesses application classes", fontsize=20, pad=30)

    # Plot Call Cycles
    # \___________________

    def plot_call_nb_cycles(
        self,
        ax,
        application_classes_data: List[CallApplicationClassData],
        nb_methods: str,
        width: float = 0.25,
        shift: int = 0,
    ):
        call_occupations = {"low": 0, "medium": 0, "high": 0}
        positions: List[float] = [0, 1, 2]
        positions = [pos + shift * width for pos in positions]

        for app_data in application_classes_data:
            if nb_methods == app_data["nb_methods_qualif"]:
                call_occupations[app_data["call_occupations_qualif"]] = mean(
                    [nb_cycles for nb_cycles in app_data["nb_cycles"] if nb_cycles != 0]
                )

        ax.bar(
            positions,
            call_occupations.values(),
            width=width,
            color="blue",
            alpha=0.5,
            label=call_occupations.keys(),
        )

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_ylim(0, 2000000)
        ax.set_xlabel("Call occupation")
        ax.set_ylabel("Number of cycles")
        # ax.set_title("Number of cycles with varying call occupation")

    def plot_all_call_nb_cycles(
        self,
        ax,
        application_classes_data1: List[CallApplicationClassData],
        application_classes_data2: List[CallApplicationClassData],
        width: float = 0.5,
    ):
        call_positions = {"low": 0, "medium": 2, "high": 4}
        nb_methods_positions = {"low": width + 0.05, "medium": 0, "high": -width - 0.05}

        for app_data in application_classes_data1:
            call_qualif = app_data["call_occupations_qualif"]
            ax.bar(
                call_positions[call_qualif]
                + nb_methods_positions[app_data["nb_methods_qualif"]],
                math.ceil(
                    mean([
                        nb_cycle for nb_cycle in app_data["nb_cycles"] if nb_cycle != 0
                    ])
                )
                / 1000,
                color="blue",
                alpha=0.5,
                width=0.23,
                label=call_qualif,
            )

        for app_data in application_classes_data2:
            call_qualif = app_data["call_occupations_qualif"]
            ax.bar(
                call_positions[call_qualif]
                + nb_methods_positions[app_data["nb_methods_qualif"]]
                + 0.25,
                math.ceil(
                    mean([
                        nb_cycle for nb_cycle in app_data["nb_cycles"] if nb_cycle != 0
                    ])
                )
                / 1000,
                color="red",
                alpha=0.5,
                width=0.23,
                label=call_qualif,
            )

        # Vertical dotted green lines
        ax.vlines(
            x=[
                1.12,
                3.12,
            ],
            ymin=0,
            ymax=1600,
            # color="green",
            # alpha=0.5,
            ls=":",
            lw=2,
        )

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_ylim(0, 1600)
        ax.set_xticks(
            [
                -0.85 * width,
                0 + 0.25 * width,
                0 + 1.35 * width,
                2 - 0.85 * width,
                2 + 0.25 * width,
                2 + 1.35 * width,
                4 - 0.85 * width,
                4 + 0.25 * width,
                4 + 1.35 * width,
            ],
            ["400", "600", "800"] * 3,
            rotation=45,
            ha="right",
            fontsize=16,
        )
        ax.set_xlim(-0.75, 5)
        ax.set_xlabel("Method mean size (in bytes)", fontsize=20)
        ax_call_occup = ax.twiny()
        ax_call_occup.set_xticks(
            [0 + 0.25 * width, 2 + 0.25 * width, 4 + 0.25 * width],
            ["1%", "3%", "6%"],
            fontsize=16,
        )
        ax_call_occup.set_xlim(-1, 5)
        ax_call_occup.set_xlabel("Call occupation (in % of method bodies)", fontsize=20)
        ax.set_ylabel("Number of cycles (in thousands of cycles)", fontsize=20)
        ax.tick_params(axis="y", labelsize=16)
        # ax.set_title("Number of cycles with varying call occupation")

    # Plot Memory Cycles
    # \___________________

    def plot_mem_nb_cycles(
        self,
        ax,
        application_classes_data: List[MemoryApplicationClassData],
        nb_methods: str,
    ):
        mem_accesses = {"low": 0, "medium": 0, "high": 0}
        for app_data in application_classes_data:
            if nb_methods == app_data["nb_methods_qualif"]:
                mem_accesses[app_data["mem_accesses_qualif"]] = mean(
                    [nb_cycles for nb_cycles in app_data["nb_cycles"] if nb_cycles != 0]
                )

        ax.bar(mem_accesses.keys(), mem_accesses.values(), color="green", alpha=0.5)
        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_ylim(0, 100)
        ax.set_xlabel("Memory instruction density")
        ax.set_ylabel("Number of cycles")
        # ax.set_title("Number of cycles with varying memory instruction density")

    def plot_all_mem_nb_cycles(
        self,
        ax,
        application_classes_data1: List[MemoryApplicationClassData],
        application_classes_data2: List[MemoryApplicationClassData],
        width: float = 0.5,
    ):
        mem_positions = {"low": 0, "medium": 2, "high": 4}
        nb_methods_positions = {"low": width + 0.05, "medium": 0, "high": -width - 0.05}

        for app_data in application_classes_data1:
            mem_qualif = app_data["mem_accesses_qualif"]
            ax.bar(
                mem_positions[mem_qualif]
                + nb_methods_positions[app_data["nb_methods_qualif"]],
                math.ceil(
                    mean([
                        nb_cycle for nb_cycle in app_data["nb_cycles"] if nb_cycle != 0
                    ])
                )
                / 1000,
                color="blue",
                alpha=0.5,
                width=0.23,
                label=mem_qualif,
            )

        for app_data in application_classes_data2:
            mem_qualif = app_data["mem_accesses_qualif"]
            ax.bar(
                mem_positions[mem_qualif]
                + nb_methods_positions[app_data["nb_methods_qualif"]]
                + 0.25,
                math.ceil(
                    mean([
                        nb_cycle for nb_cycle in app_data["nb_cycles"] if nb_cycle != 0
                    ])
                )
                / 1000,
                color="red",
                alpha=0.5,
                width=0.23,
                label=mem_qualif,
            )

        # Vertical dotted green lines
        ax.vlines(
            x=[
                1.12,
                3.12,
            ],
            ymin=0,
            ymax=1600,
            # color="green",
            # alpha=0.5,
            ls=":",
            lw=2,
        )

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_ylim(0, 500)
        ax.set_xticks(
            [
                -0.85 * width,
                0 + 0.25 * width,
                0 + 1.35 * width,
                2 - 0.85 * width,
                2 + 0.25 * width,
                2 + 1.35 * width,
                4 - 0.85 * width,
                4 + 0.25 * width,
                4 + 1.35 * width,
            ],
            ["400", "600", "800"] * 3,
            rotation=45,
            ha="right",
            fontsize=16,
        )
        ax.set_xlim(-0.75, 5)
        ax.set_xlabel("Method mean size (in bytes)", fontsize=20)
        ax_mem_intens = ax.twiny()
        ax_mem_intens.set_xlim(-0.75, 5)
        ax_mem_intens.set_xticks(
            [0 + 0.25 * width, 2 + 0.25 * width, 4 + 0.25 * width],
            ["4%", "8%", "12%"],
            fontsize=16,
        )

        ax_mem_intens.set_xlabel("Memory accesses (% of method bodies)", fontsize=20)
        ax.set_ylabel("Number of cycles (thousands of cycles)", fontsize=20)
        ax.tick_params(axis="y", labelsize=16)
        # ax.set_title("Number of cycles with varying call occupation")

    # Plot Call CPIs
    # \___________________

    def plot_call_cpis(
        self,
        ax,
        application_classes_data: List[CallApplicationClassData],
        nb_methods: str,
    ):
        call_occupations = {"low": 0, "medium": 0, "high": 0}
        for app_data in application_classes_data:
            if nb_methods == app_data["nb_methods_qualif"]:
                call_occupations[app_data["call_occupations_qualif"]] = mean(
                    app_data["cpis"]
                )

        ax.bar(
            call_occupations.keys(), call_occupations.values(), color="red", alpha=0.5
        )
        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_ylim(0, 5)
        ax.set_xlabel("Call Occupation")
        ax.set_ylabel("CPI")
        # ax.set_title("CPIs with varying call density")

    # Plot Memory Cycles
    # \___________________

    def plot_mem_cpis(
        self,
        ax,
        application_classes_data: List[MemoryApplicationClassData],
        nb_methods: str,
    ):
        mem_accesses = {"low": 0, "medium": 0, "high": 0}
        for app_data in application_classes_data:
            if nb_methods == app_data["nb_methods_qualif"]:
                mem_accesses[app_data["mem_accesses_qualif"]] = mean(app_data["cpis"])

        ax.bar(mem_accesses.keys(), mem_accesses.values(), color="red", alpha=0.5)
        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_ylim(0, 5)
        ax.set_xlabel("Memory accesses")
        ax.set_ylabel("CPI")
        # ax.set_title("CPIs with varying memory instruction density")

    def plot_overhead_calls(
        self,
        ax,
        overhead_call_data: List[OverheadCallComparisonData],
        width: float = 0.5,
    ):
        call_positions = {"low": 0, "medium": 2, "high": 4}
        nb_methods_positions = {"low": width + 0.05, "medium": 0, "high": -width - 0.05}

        for overhead_data in overhead_call_data:
            call_qualif = overhead_data["call_occupations_qualif"]
            ax.bar(
                call_positions[call_qualif]
                + nb_methods_positions[overhead_data["nb_methods_qualif"]],
                overhead_data["geomean_cycle_overhead"],
                color="green",
                alpha=0.7,
                width=0.23,
                hatch="/",
            )
            ax.bar(
                call_positions[call_qualif]
                + nb_methods_positions[overhead_data["nb_methods_qualif"]]
                + 0.25,
                overhead_data["geomean_cpi_overhead"],
                color="green",
                alpha=0.3,
                width=0.23,
                hatch="//",
            )
        ax.axhline(y=1, color="black")

        ax.set_xticks(
            [
                -0.85 * width,
                0 + 0.25 * width,
                0 + 1.35 * width,
                2 - 0.85 * width,
                2 + 0.25 * width,
                2 + 1.35 * width,
                4 - 0.85 * width,
                4 + 0.25 * width,
                4 + 1.35 * width,
            ],
            ["1-1", "1-2", "1-3", "2-1", "2-2", "2-3", "3-1", "3-2", "3-3"],
            fontsize=16,
        )
        ax.set_xlim(-0.75, 5)

        ax.grid(axis="y")
        ax.set_ylim(0.97, 1.03)
        ax.set_xlabel("Configuration (call occupation - method size)", fontsize=20)
        ax.set_ylabel("Overhead (normalized to baseline)", fontsize=20)
        ax.tick_params(axis="y", labelsize=16)

    def plot_overhead_mem(
        self,
        ax,
        overhead_mem_data: List[OverheadMemoryComparisonData],
        width: float = 0.5,
    ):
        mem_positions = {"low": 0, "medium": 2, "high": 4}
        nb_methods_positions = {"low": width + 0.05, "medium": 0, "high": -width - 0.05}

        for overhead_data in overhead_mem_data:
            mem_qualif = overhead_data["mem_accesses_qualif"]
            ax.bar(
                mem_positions[mem_qualif]
                + nb_methods_positions[overhead_data["nb_methods_qualif"]],
                overhead_data["geomean_cycle_overhead"],
                color="blue",
                alpha=0.7,
                width=0.23,
                hatch="/",
                label=mem_qualif,
            )
            ax.bar(
                mem_positions[mem_qualif]
                + nb_methods_positions[overhead_data["nb_methods_qualif"]]
                + 0.25,
                overhead_data["geomean_cpi_overhead"],
                color="blue",
                alpha=0.3,
                width=0.23,
                hatch="//",
            )
        ax.axhline(y=1, color="black")

        ax.set_xticks(
            [
                -0.85 * width,
                0 + 0.25 * width,
                0 + 1.35 * width,
                2 - 0.85 * width,
                2 + 0.25 * width,
                2 + 1.35 * width,
                4 - 0.85 * width,
                4 + 0.25 * width,
                4 + 1.35 * width,
            ],
            ["1-1", "1-2", "1-3", "2-1", "2-2", "2-3", "3-1", "3-2", "3-3"],
            fontsize=16,
        )
        ax.set_xlim(-0.75, 5)

        ax.grid(axis="y")
        ax.set_ylim(0.97, 1.03)
        ax.set_xlabel("Configuration (memory access - method size)", fontsize=20)
        ax.set_ylabel("Overhead (normalized to baseline)", fontsize=20)
        ax.tick_params(axis="y", labelsize=16)


def check_overhead_call(
    baseline: List[CallApplicationClassData],
    jitdom: List[CallApplicationClassData],
    call_qualifier: str,
    method_qualifier: str,
):
    current_baseline_call_data: CallApplicationClassData
    for call_data_base in baseline:
        if (
            call_data_base["call_occupations_qualif"] == call_qualifier
            and call_data_base["nb_methods_qualif"] == method_qualifier
        ):
            current_baseline_call_data = call_data_base

    current_jitdom_call_data: CallApplicationClassData
    for call_data_jitdom in jitdom:
        if (
            call_data_jitdom["call_occupations_qualif"] == call_qualifier
            and call_data_jitdom["nb_methods_qualif"] == method_qualifier
        ):
            current_jitdom_call_data = call_data_jitdom

    cycle_overhead: List[int] = []
    cycle_overhead_percent: List[float] = []
    for base_cycle, jitdom_cycle in zip(
        current_baseline_call_data["nb_cycles"],
        current_jitdom_call_data["nb_cycles"],
    ):
        diff = jitdom_cycle - base_cycle
        cycle_overhead.append(diff)
        cycle_overhead_percent.append(
            (diff / max(jitdom_cycle, base_cycle) * 100 + 100) / 100 if diff != 0 else 1
        )

    product_cycle = 1.0
    product_cycle_percent = 1.0
    for cycle, cycle_percent in zip(cycle_overhead, cycle_overhead_percent):
        product_cycle *= cycle if cycle != 0 else 1.0
        product_cycle_percent *= cycle_percent if cycle_percent != 0 else 1.0

    # geomean_cycle = math.pow(product_cycle, 1.0 / len(cycle_overhead))
    geomean_cycle_percent = math.pow(
        product_cycle_percent, 1.0 / len(cycle_overhead_percent)
    )

    cpi_overhead: List[float] = []
    cpi_overhead_percent: List[float] = []
    for base_cpi, jitdom_cpi in zip(
        current_baseline_call_data["cpis"],
        current_jitdom_call_data["cpis"],
    ):
        diff_cpi = jitdom_cpi - base_cpi
        cpi_overhead.append(diff_cpi)
        cpi_overhead_percent.append(
            (diff_cpi / max(jitdom_cpi, base_cpi) * 100 + 100) / 100
            if diff_cpi != 0
            else 1
        )

    product_cpi = 1.0
    product_cpi_percent = 1.0
    for cpi, cpi_percent in zip(cpi_overhead, cpi_overhead_percent):
        product_cpi *= cpi if cpi != 0 else 1.0
        product_cpi_percent *= cpi_percent if cpi_percent != 0 else 1.0
    # geomean_cpi = math.pow(product_cpi, 1.0 / len(cpi_overhead))
    geomean_cpi_percent = math.pow(product_cpi_percent, 1.0 / len(cpi_overhead_percent))

    mean_call_occup = mean(current_jitdom_call_data["call_occupations"])
    mean_method_size = mean(current_jitdom_call_data["mean_method_sizes"])

    print(
        "Overhead between baseline and JITDomain for"
        f" {call_qualifier}({mean_call_occup}) calls"
        f" {method_qualifier}({mean_method_size * 4}) methods:\n"
        # f" cycle overhead: {cycle_overhead}\n"
        # f" cycle% overhead: {cycle_overhead_percent}\n"
        # f" geomean cycle overhead: {geomean_cycle}\n"
        f" geomean cycle% overhead: {geomean_cycle_percent}\n"
        # f" cpi overhead: {cpi_overhead}\n"
        # f" cpi% overhead: {cpi_overhead_percent}\n"
        # f" geomean cpi overhead: {geomean_cpi}\n"
        f" geomean cpi% overhead:   {geomean_cpi_percent}\n"
        "\\________________________________________________\n\n"
    )

    overhead_call_cmp_data: OverheadCallComparisonData = {
        "name_1": baseline[0]["name"],
        "name_2": jitdom[0]["name"],
        "nb_methods_qualif": method_qualifier,
        "call_occupations_qualif": call_qualifier,
        "cycle_overhead": cycle_overhead,
        "cycle_overhead_percent": cycle_overhead_percent,
        "geomean_cycle_overhead": geomean_cycle_percent,
        "cpi_overhead": cpi_overhead,
        "cpi_overhead_percent": cpi_overhead_percent,
        "geomean_cpi_overhead": geomean_cpi_percent,
    }
    return overhead_call_cmp_data


def check_overhead_mem(
    baseline: List[MemoryApplicationClassData],
    jitdom: List[MemoryApplicationClassData],
    mem_qualifier: str,
    method_qualifier: str,
):
    current_baseline_mem_data: MemoryApplicationClassData
    for mem_data_base in baseline:
        if (
            mem_data_base["mem_accesses_qualif"] == mem_qualifier
            and mem_data_base["nb_methods_qualif"] == method_qualifier
        ):
            current_baseline_mem_data = mem_data_base

    current_jitdom_mem_data: MemoryApplicationClassData
    for mem_data_jitdom in jitdom:
        if (
            mem_data_jitdom["mem_accesses_qualif"] == mem_qualifier
            and mem_data_jitdom["nb_methods_qualif"] == method_qualifier
        ):
            current_jitdom_mem_data = mem_data_jitdom

    cycle_overhead: List[int] = []
    cycle_overhead_percent: List[float] = []
    for base_cycle, jitdom_cycle in zip(
        current_baseline_mem_data["nb_cycles"],
        current_jitdom_mem_data["nb_cycles"],
    ):
        diff = jitdom_cycle - base_cycle
        cycle_overhead.append(diff)
        cycle_overhead_percent.append(
            (diff / max(jitdom_cycle, base_cycle) * 100 + 100) / 100 if diff != 0 else 1
        )

    product_cycle = 1.0
    product_cycle_percent = 1.0
    for cycle, cycle_percent in zip(cycle_overhead, cycle_overhead_percent):
        product_cycle *= cycle if cycle != 0 else 1.0
        product_cycle_percent *= cycle_percent if cycle_percent != 0 else 1.0

    # geomean_cycle = math.pow(product_cycle, 1.0 / len(cycle_overhead))
    geomean_cycle_percent = math.pow(
        product_cycle_percent, 1.0 / len(cycle_overhead_percent)
    )

    cpi_overhead: List[float] = []
    cpi_overhead_percent: List[float] = []
    for base_cpi, jitdom_cpi in zip(
        current_baseline_mem_data["cpis"],
        current_jitdom_mem_data["cpis"],
    ):
        diff_cpi = jitdom_cpi - base_cpi
        cpi_overhead.append(diff_cpi)
        cpi_overhead_percent.append(
            (diff_cpi / max(jitdom_cpi, base_cpi) * 100 + 100) / 100
            if diff_cpi != 0
            else 1
        )

    product_cpi = 1.0
    product_cpi_percent = 1.0
    for cpi, cpi_percent in zip(cpi_overhead, cpi_overhead_percent):
        product_cpi *= cpi if cpi != 0 else 1.0
        product_cpi_percent *= cpi_percent if cpi_percent != 0 else 1.0
    # geomean_cpi = math.pow(product_cpi, 1.0 / len(cpi_overhead))
    geomean_cpi_percent = math.pow(product_cpi_percent, 1.0 / len(cpi_overhead_percent))

    mean_mem_access = mean(current_jitdom_mem_data["mem_accesses"])
    mean_method_size = mean(current_jitdom_mem_data["mean_method_sizes"])

    print(
        "Overhead between baseline and JITDomain for"
        f" {mem_qualifier}({mean_mem_access}) memory"
        f" {method_qualifier}({mean_method_size * 4}) methods:\n"
        # f" cycle overhead: {cycle_overhead}\n"
        # f" cycle% overhead: {cycle_overhead_percent}\n"
        # f" geomean cycle overhead: {geomean_cycle}\n"
        f" geomean cycle% overhead: {geomean_cycle_percent}\n"
        # f" cpi overhead: {cpi_overhead}\n"
        # f" cpi% overhead: {cpi_overhead_percent}\n"
        # f" geomean cpi overhead: {geomean_cpi}\n"
        f" geomean cpi% overhead:   {geomean_cpi_percent}\n"
        "\\________________________________________________\n\n"
    )

    overhead_mem_cmp_data: OverheadMemoryComparisonData = {
        "name_1": baseline[0]["name"],
        "name_2": jitdom[0]["name"],
        "nb_methods_qualif": method_qualifier,
        "mem_accesses_qualif": mem_qualifier,
        "cycle_overhead": cycle_overhead,
        "cycle_overhead_percent": cycle_overhead_percent,
        "geomean_cycle_overhead": geomean_cycle_percent,
        "cpi_overhead": cpi_overhead,
        "cpi_overhead_percent": cpi_overhead_percent,
        "geomean_cpi_overhead": geomean_cpi_percent,
    }
    return overhead_mem_cmp_data


if __name__ == "__main__":
    import matplotlib.pyplot as plt

    plotter = Plotter()

    # cva6_data_folder = "toccata/results/manuscript-none-cva6jitdom-2/"
    # call_application_classes_cva6: List[CallApplicationClassData] = (
    #     plotter.process_call_application_classes([""], cva6_data_folder, True)
    # )
    # mem_application_classes_cva6: List[MemoryApplicationClassData] = (
    #     plotter.process_mem_application_classes([""], cva6_data_folder, True)
    # )

    # rocket_data_folder = "toccata/results/manuscript-none-rocket-2/"
    # call_application_classes_rocket: List[CallApplicationClassData] = (
    #     plotter.process_call_application_classes([""], rocket_data_folder, True)
    # )
    # mem_application_classes_rocket: List[MemoryApplicationClassData] = (
    #     plotter.process_mem_application_classes([""], rocket_data_folder, True)
    # )

    # fig_app, axs_app = plt.subplots(1, 2)
    # fig_app.set_size_inches(14, 7)

    # plotter.plot_call_application_classes(axs_app[0], call_application_classes_cva6)
    # plotter.plot_mem_application_classes(axs_app[1], mem_application_classes_cva6)

    # All in one call/mem nb cycles
    # \_______________________________

    # fig_cycles, axs_cycles = plt.subplots(1, 2)
    # fig_cycles.set_size_inches(18, 9)

    # plotter.plot_all_call_nb_cycles(
    #     axs_cycles[0],
    #     application_classes_data1=call_application_classes_cva6,
    #     application_classes_data2=call_application_classes_rocket,
    # )
    # plotter.plot_all_mem_nb_cycles(
    #     axs_cycles[1],
    #     application_classes_data1=mem_application_classes_cva6,
    #     application_classes_data2=mem_application_classes_rocket,
    # )
    # plt.show()
    # fig_app.savefig("gigue_app_classes.png", dpi=200)
    # fig_cycles.savefig("gigue_app_exec.png", dpi=200)

    # =================================================
    # Compare OVERHEADS
    # =================================================

    with open(
        "toccata/results/manuscript-none-cva6jitdom-2/calls_plot_data.json", "r"
    ) as data:
        call_cva6_base: List[CallApplicationClassData] = json.load(data)

    with open(
        "toccata/results/manuscript-rimifull-cva6jitdom-3/calls_plot_data.json", "r"
    ) as data:
        call_cva6_jitdom: List[CallApplicationClassData] = json.load(data)

    with open(
        "toccata/results/manuscript-none-cva6jitdom-2/calls_plot_data.json", "r"
    ) as data:
        call_rocket: List[CallApplicationClassData] = json.load(data)

    call_overhead_data: List[OverheadCallComparisonData] = []
    print("\\_____________ CALLS ______________________\n\n")
    for call_qualif in ["low", "medium", "high"]:
        for method_qualif in ["low", "medium", "high"]:
            call_overhead_data.append(
                check_overhead_call(
                    call_cva6_base, call_cva6_jitdom, call_qualif, method_qualif
                )
            )

    fig_ov_calls = plt.figure()
    axs_ov_calls = plt.axes()
    fig_ov_calls.set_size_inches(14, 6)

    plotter.plot_overhead_calls(axs_ov_calls, call_overhead_data)
    fig_ov_calls.savefig("gigue_overhead_calls.png", dpi=200)

    # Compare
    with open(
        "toccata/results/manuscript-none-cva6jitdom-2/mem_plot_data.json", "r"
    ) as data:
        mem_cva6_base: List[MemoryApplicationClassData] = json.load(data)

    with open(
        "toccata/results/manuscript-rimifull-cva6jitdom-3/mem_plot_data.json", "r"
    ) as data:
        mem_cva6_jitdom: List[MemoryApplicationClassData] = json.load(data)

    with open(
        "toccata/results/manuscript-none-cva6jitdom-2/mem_plot_data.json", "r"
    ) as data:
        mem_rocket: List[MemoryApplicationClassData] = json.load(data)

    print("\\_____________ MEMORY ______________________\n\n")

    mem_overhead_data: List[OverheadMemoryComparisonData] = []
    for mem_qualif in ["low", "medium", "high"]:
        for method_qualif in ["low", "medium", "high"]:
            mem_overhead_data.append(
                check_overhead_mem(
                    mem_cva6_base, mem_cva6_jitdom, mem_qualif, method_qualif
                )
            )

    fig_ov_mem = plt.figure()
    axs_ov_mem = plt.axes()
    fig_ov_mem.set_size_inches(14, 6)

    plotter.plot_overhead_mem(axs_ov_mem, mem_overhead_data)
    fig_ov_mem.savefig("gigue_overhead_mem.png", dpi=200)

    # 3x3 call nb cycles and CPI
    # \____________________________

    # fig_calls, axs_calls = plt.subplots(2, 3)
    # plotter.plot_call_nb_cycles(axs_calls[0, 0], call_application_classes, "low")
    # plotter.plot_call_nb_cycles(
    #     axs_calls[0, 1], call_application_classes, "medium", shift=1
    # )
    # plotter.plot_call_nb_cycles(
    #     axs_calls[0, 2], call_application_classes, "high", shift=2
    # )

    # plotter.plot_call_cpis(axs_calls[1, 0], call_application_classes, "low")
    # plotter.plot_call_cpis(axs_calls[1, 1], call_application_classes, "medium")
    # plotter.plot_call_cpis(axs_calls[1, 2], call_application_classes, "high")

    # fig_calls.tight_layout()
    # for ax, col in zip(axs_calls[0], ["50 methods", "100 methods", "200 methods"]):
    #     ax.set_title(col)
    # plt.xticks(["low", "medium", "high"])
    # plt.show()

    # fig_calls, axs_calls = plt.subplots(2, 3)
    # plotter.plot_call_nb_cycles(axs_calls[0, 0], call_application_classes, "low")
    # plotter.plot_call_nb_cycles(axs_calls[0, 1], call_application_classes, "medium")
    # plotter.plot_call_nb_cycles(axs_calls[0, 2], call_application_classes, "high")

    # plotter.plot_call_cpis(axs_calls[1, 0], call_application_classes, "low")
    # plotter.plot_call_cpis(axs_calls[1, 1], call_application_classes, "medium")
    # plotter.plot_call_cpis(axs_calls[1, 2], call_application_classes, "high")

    # fig_calls.tight_layout()
    # for ax, col in zip(axs_calls[0], ["50 methods", "100 methods", "200 methods"]):
    #     ax.set_title(col)
    # plt.xticks(["low", "medium", "high"])
    # plt.show()

    # fig_mem, axs_mem = plt.subplots(2, 3)
    # plotter.plot_mem_nb_cycles(axs_mem[0, 0], mem_application_classes, "low")
    # plotter.plot_mem_nb_cycles(axs_mem[0, 1], mem_application_classes, "medium")
    # plotter.plot_mem_nb_cycles(axs_mem[0, 2], mem_application_classes, "high")

    # plotter.plot_mem_cpis(axs_mem[1, 0], mem_application_classes, "low")
    # plotter.plot_mem_cpis(axs_mem[1, 1], mem_application_classes, "medium")
    # plotter.plot_mem_cpis(axs_mem[1, 2], mem_application_classes, "high")
    # fig_mem.tight_layout()
    # for ax, col in zip(axs_calls[0], ["50 methods", "100 methods", "200 methods"]):
    #     ax.set_title(col)
    # plt.xticks(["low", "medium", "high"])
    # plt.show()
