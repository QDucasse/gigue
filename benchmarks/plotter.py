from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Callable, List

import matplotlib.pyplot as plt

from benchmarks.data import (
    CallApplicationClassData,
    EmulationData,
    FullData,
    MemoryApplicationClassData,
    RunData,
    TracingData,
)
from gigue.helpers import mean

if TYPE_CHECKING:
    from matplotlib.axes import Axes


class Plotter:
    # Config define the different application classes
    LOCKED_RESULTS_PATH = "benchmarks/results/locked/"
    CALL_APPLICATIONS_PATH = f"{LOCKED_RESULTS_PATH}calls/"
    MEM_APPLICATIONS_PATH = f"{LOCKED_RESULTS_PATH}memory/"

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

    # Metric 2: Call Occupation (% of body size dedicated to calls)
    # \_______________________________________________________________

    def extract_run_call_density(self, run_data: RunData):
        call_occupation: float = run_data["generation_data"][
            "mean_method_call_occupation"
        ]
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
        mem_access: float = mem_instrs_nb / instrs_nb * 100
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
        cpi: float = cycles_nb / instrs_nb
        return cpi

    def extract_cpis(self, full_data: FullData):
        return self.extract_from_full_data(
            full_data=full_data, extraction_method=self.extract_cycle_per_instruction
        )

    # Extraction from call applications
    # \____________________________________

    def process_call_application_classes(
        self, isolation_types: List[str], store_plot_data: bool = False
    ) -> List[CallApplicationClassData]:
        application_classes_data: List[CallApplicationClassData] = []
        for isolation_type in isolation_types:
            call_apps_path: str = Plotter.CALL_APPLICATIONS_PATH + isolation_type
            for call_app_path in os.listdir(call_apps_path):
                with open(f"{call_apps_path}/{call_app_path}/data.json", "r") as data:
                    full_data: FullData = json.load(data)
                    # Extract method nb
                    nb_methods: List[int] = self.extract_run_nb_methods(
                        full_data["run_data"][0]
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
                    splitted = str(call_app_path).split("_")
                    nb_methods_qualif = splitted[0]
                    call_occupations_qualif = splitted[3]
                    call_application_class_data: CallApplicationClassData = {
                        "name": str(call_app_path),
                        "nb_methods_qualif": nb_methods_qualif,
                        "call_occupations_qualif": call_occupations_qualif,
                        "isolation": isolation_type,
                        "nb_methods": nb_methods,
                        "call_occupations": call_occupations,
                        "nb_cycles": nb_cycles,
                        "cpis": cpis,
                    }
                    application_classes_data.append(call_application_class_data)
        if store_plot_data:
            with open(
                f"{plotter.LOCKED_RESULTS_PATH}/calls_plot_data.json", "w"
            ) as outfile:
                json.dump(
                    application_classes_data, outfile, indent=2, separators=(",", ": ")
                )
        return application_classes_data

    # Extraction from mem applications
    # \____________________________________

    def process_mem_application_classes(
        self, isolation_types: List[str], store_plot_data: bool = False
    ) -> List[MemoryApplicationClassData]:
        application_classes_data: List[MemoryApplicationClassData] = []
        for isolation_type in isolation_types:
            mem_apps_path: str = Plotter.MEM_APPLICATIONS_PATH + isolation_type
            for mem_app_path in os.listdir(mem_apps_path):
                with open(f"{mem_apps_path}/{mem_app_path}/data.json", "r") as data:
                    full_data: FullData = json.load(data)
                    # Extract method nb
                    nb_methods: List[int] = self.extract_nb_methods(full_data)
                    # Extract mem density
                    mem_accesses: List[float] = self.extract_mem_accesses(full_data)
                    # Extract cycle nb
                    nb_cycles: List[int] = self.extract_cycles(full_data)
                    # Extract CPI
                    cpis: List[float] = self.extract_cpis(full_data)
                    # Extract qualifiers
                    splitted = str(mem_app_path).split("_")
                    nb_methods_qualif = splitted[0]
                    mem_accesses_qualif = splitted[3]
                    mem_application_class_data: MemoryApplicationClassData = {
                        "name": str(mem_app_path),
                        "nb_methods_qualif": nb_methods_qualif,
                        "mem_accesses_qualif": mem_accesses_qualif,
                        "isolation": isolation_type,
                        "nb_methods": nb_methods,
                        "mem_accesses": mem_accesses,
                        "nb_cycles": nb_cycles,
                        "cpis": cpis,
                    }
                    application_classes_data.append(mem_application_class_data)
        if store_plot_data:
            with open(
                f"{plotter.LOCKED_RESULTS_PATH}/mem_plot_data.json", "w"
            ) as outfile:
                json.dump(
                    application_classes_data, outfile, indent=2, separators=(",", ": ")
                )
        return application_classes_data

    # Plot Calls Application Classes
    # \__________________________________

    def plot_call_application_classes(
        self, ax, application_classes_data: List[CallApplicationClassData]
    ):
        plot_colors = {
            "low": 0.2,
            "medium": 0.5,
            "high": 0.9,
        }
        for app_data in application_classes_data:
            ax.scatter(
                [app_data["nb_methods"]] * len(app_data["call_occupations"]),
                app_data["call_occupations"],
                color="blue",
                alpha=plot_colors[app_data["call_occupations_qualif"]],
            )

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_xlabel("Method number")
        ax.set_ylabel("Call occupation (%)")
        ax.set_title("Call occupation application classes")

    # Plot Memory Application Classes
    # \__________________________________

    def plot_mem_application_classes(
        self, ax: Axes, application_classes_data: List[MemoryApplicationClassData]
    ):
        plot_colors = {
            "low": (0.2),
            "medium": (0.5),
            "high": (0.9),
        }
        for app_data in application_classes_data:
            ax.scatter(
                app_data["nb_methods"],
                app_data["mem_accesses"],
                color="green",
                alpha=plot_colors[app_data["mem_accesses_qualif"]],
            )

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_xlabel("Method number")
        ax.set_ylabel("Memory accesses (%)")
        ax.set_title("Memory accesses application classes")

    # Plot Call Cycles
    # \___________________

    def plot_call_nb_cycles(
        self,
        ax,
        application_classes_data: List[CallApplicationClassData],
        nb_methods: str,
    ):
        call_occupations = {"low": 0, "medium": 0, "high": 0}
        for app_data in application_classes_data:
            if nb_methods == app_data["nb_methods_qualif"]:
                call_occupations[app_data["call_occupations_qualif"]] = mean(
                    app_data["nb_cycles"]
                )

        ax.bar(
            call_occupations.keys(), call_occupations.values(), color="blue", alpha=0.5
        )

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_xlabel("Call occupation")
        ax.set_ylabel("Number of cycles")
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
                    app_data["nb_cycles"]
                )

        ax.bar(mem_accesses.keys(), mem_accesses.values(), color="green", alpha=0.5)
        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_xlabel("Memory instruction density")
        ax.set_ylabel("Number of cycles")
        # ax.set_title("Number of cycles with varying memory instruction density")

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
        ax.set_xlabel("Memory accesses")
        ax.set_ylabel("CPI")
        # ax.set_title("CPIs with varying memory instruction density")


if __name__ == "__main__":
    fig_app, axs_app = plt.subplots(1, 2)
    plotter = Plotter()
    call_application_classes: List[
        CallApplicationClassData
    ] = plotter.process_call_application_classes(["no_isolation"], True)
    mem_application_classes: List[
        MemoryApplicationClassData
    ] = plotter.process_mem_application_classes(["no_isolation"], True)
    plotter.plot_call_application_classes(axs_app[0], call_application_classes)
    plotter.plot_mem_application_classes(axs_app[1], mem_application_classes)
    plt.show()

    fig_calls, axs_calls = plt.subplots(2, 3)
    plotter.plot_call_nb_cycles(axs_calls[0, 0], call_application_classes, "low")
    plotter.plot_call_nb_cycles(axs_calls[0, 1], call_application_classes, "medium")
    plotter.plot_call_nb_cycles(axs_calls[0, 2], call_application_classes, "high")

    plotter.plot_call_cpis(axs_calls[1, 0], call_application_classes, "low")
    plotter.plot_call_cpis(axs_calls[1, 1], call_application_classes, "medium")
    plotter.plot_call_cpis(axs_calls[1, 2], call_application_classes, "high")

    fig_calls.tight_layout()
    for ax, col in zip(axs_calls[0], ["50 methods", "100 methods", "500 methods"]):
        ax.set_title(col)
    plt.xticks(["low", "medium", "high"])
    plt.show()

    fig_mem, axs_mem = plt.subplots(2, 3)
    plotter.plot_mem_nb_cycles(axs_mem[0, 0], mem_application_classes, "low")
    plotter.plot_mem_nb_cycles(axs_mem[0, 1], mem_application_classes, "medium")
    plotter.plot_mem_nb_cycles(axs_mem[0, 2], mem_application_classes, "high")

    plotter.plot_mem_cpis(axs_mem[1, 0], mem_application_classes, "low")
    plotter.plot_mem_cpis(axs_mem[1, 1], mem_application_classes, "medium")
    plotter.plot_mem_cpis(axs_mem[1, 2], mem_application_classes, "high")
    fig_mem.tight_layout()
    for ax, col in zip(axs_calls[0], ["50 methods", "100 methods", "500 methods"]):
        ax.set_title(col)
    plt.xticks(["low", "medium", "high"])
    plt.show()
