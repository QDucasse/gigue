from __future__ import annotations

import json
import math
import os
import re
from typing import TYPE_CHECKING, Callable, List, Optional

import matplotlib.pyplot as plt

from gigue.helpers import mean
from toccata.data import (
    CallApplicationClassData,
    EmulationData,
    FullData,
    MemoryApplicationClassData,
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
        for isolation_type in isolation_types:
            call_apps_path: str = experiments_path + "calls/" + isolation_type
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
                    call_occupations: List[float] = self.extract_call_occupations(
                        full_data
                    )
                    # Extract cycle nb
                    nb_cycles: List[int] = self.extract_cycles(full_data)
                    # Extract CPI
                    cpis: List[float] = self.extract_cpis(full_data)
                    # Extract qualifiers
                    config_name = full_data["config_data"]["config_name"]
                    pattern = (
                        re.escape(config_name) + r"_(\w+)_nbmethods_(\w+)_calloccup"
                    )
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
                        "isolation": isolation_type,
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
        for isolation_type in isolation_types:
            mem_apps_path: str = experiments_path + "memory/" + isolation_type
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
                    pattern = (
                        re.escape(config_name) + r"_(\w+)_nbmethods_(\w+)_memaccess"
                    )
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
                        "isolation": isolation_type,
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
                app_data["mean_method_sizes"],
                app_data["call_occupations"],
                color="blue",
                alpha=Plotter.PLOT_COLORS[app_data["call_occupations_qualif"]],
            )

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_ylim(0, 50)
        ax.set_xlabel("Mean method size")
        ax.set_ylabel("Call occupation (%)")
        ax.set_title("Call occupation application classes")

    # Plot Memory Application Classes
    # \__________________________________

    def plot_mem_application_classes(
        self, ax: Axes, application_classes_data: List[MemoryApplicationClassData]
    ):
        for app_data in application_classes_data:
            ax.scatter(
                # app_data["nb_methods"],
                app_data["mean_method_sizes"],
                app_data["mem_accesses"],
                color="green",
                alpha=Plotter.PLOT_COLORS[app_data["mem_accesses_qualif"]],
            )

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_ylim(0, 50)
        ax.set_xlabel("Mean method size")
        ax.set_ylabel("Memory accesses (%)")
        ax.set_title("Memory accesses application classes")

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
        ax.set_ylim(0, 210000)
        ax.set_xlabel("Call occupation")
        ax.set_ylabel("Number of cycles")
        # ax.set_title("Number of cycles with varying call occupation")

    def plot_all_call_nb_cycles(
        self,
        ax,
        application_classes_data: List[CallApplicationClassData],
        width: float = 0.25,
    ):
        call_positions = {"low": 0, "medium": 1, "high": 2}
        nb_methods_positions = {"low": 0, "medium": width, "high": 2 * width}

        for app_data in application_classes_data:
            call_qualif = app_data["call_occupations_qualif"]
            ax.bar(
                call_positions[call_qualif]
                + nb_methods_positions[app_data["nb_methods_qualif"]],
                math.ceil(mean(app_data["nb_cycles"])) / 1000,
                color="blue",
                alpha=Plotter.PLOT_COLORS[call_qualif],
                width=width - 0.02,
                label=call_qualif,
            )

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_ylim(0, 250)
        ax.set_xticks([width, 1 + width, 2 + width], ["low", "medium", "high"])
        ax.set_xlabel("Call occupation (in % of executed instructions)")
        ax.set_ylabel("Number of cycles (in thousands of cycles)")
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
        application_classes_data: List[MemoryApplicationClassData],
        width: float = 0.25,
    ):
        mem_positions = {"low": 0, "medium": 1, "high": 2}
        nb_methods_positions = {"low": 0, "medium": width, "high": 2 * width}

        for app_data in application_classes_data:
            mem_qualif = app_data["mem_accesses_qualif"]
            ax.bar(
                mem_positions[mem_qualif]
                + nb_methods_positions[app_data["nb_methods_qualif"]],
                math.ceil(mean(app_data["nb_cycles"])) / 1000,
                color="green",
                alpha=Plotter.PLOT_COLORS[mem_qualif],
                width=width - 0.02,
                label=mem_qualif,
            )

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_ylim(0, 250)
        ax.set_xticks([width, 1 + width, 2 + width], ["low", "medium", "high"])
        ax.set_xlabel("Memory accesses (% of executed instructions)")
        ax.set_ylabel("Number of cycles (thousands of cycles)")
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


if __name__ == "__main__":
    import matplotlib

    font = {"weight": "bold", "size": 20}

    matplotlib.rc("font", **font)

    fig_app, axs_app = plt.subplots(1, 2)
    plotter = Plotter()
    call_application_classes: List[CallApplicationClassData] = (
        plotter.process_call_application_classes(
            [""], "toccata/results/manuscript-no-isolation-cva6/", True
        )
    )
    mem_application_classes: List[MemoryApplicationClassData] = (
        plotter.process_mem_application_classes(
            [""], "toccata/results/manuscript-no-isolation-cva6/", True
        )
    )
    plotter.plot_call_application_classes(axs_app[0], call_application_classes)
    plotter.plot_mem_application_classes(axs_app[1], mem_application_classes)
    plt.show()

    # All in one call/mem nb cycles
    # \_______________________________

    fig_cycles, axs_cycles = plt.subplots(1, 2)
    plotter.plot_all_call_nb_cycles(axs_cycles[0], call_application_classes)
    plotter.plot_all_mem_nb_cycles(axs_cycles[1], mem_application_classes)
    plt.show()

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
