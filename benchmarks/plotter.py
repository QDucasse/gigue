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
        pics_ratio: float = full_data["config_data"]["input_data"]["pics_ratio"]
        for i in range(nb_runs):
            run_data = full_data["run_data"][i]
            extracted_app_info = extraction_method(run_data, pics_ratio)
            extracted_class_info.append(extracted_app_info)
        return extracted_class_info

    # Method density (aka number of methods)
    # \________________________________________

    def extract_run_method_density(self, run_data: RunData, pics_ratio: float):
        mean_method_size: float = run_data["generation_data"]["mean_method_size"]
        pics_mean_method_size: float = run_data["generation_data"][
            "pics_mean_method_size"
        ]
        method_density = (
            1 - -pics_ratio
        ) * mean_method_size + pics_ratio * pics_mean_method_size
        return method_density

    def extract_method_densities(self, full_data: FullData):
        return self.extract_from_full_data(
            full_data=full_data, extraction_method=self.extract_run_method_density
        )

    # Call presence (aka how filled are the methods with calls)
    # \____________________________________________________________

    def extract_run_call_density(self, run_data: RunData, pics_ratio: float):
        mean_method_call_nb: float = run_data["generation_data"]["mean_method_call_nb"]
        mean_method_call_depth: float = run_data["generation_data"][
            "mean_method_call_depth"
        ]
        pics_mean_method_call_nb: float = run_data["generation_data"][
            "pics_mean_method_call_nb"
        ]
        pics_mean_method_call_depth: float = run_data["generation_data"][
            "pics_mean_method_call_depth"
        ]
        call_density = (
            (1 - -pics_ratio) * mean_method_call_nb * mean_method_call_depth
            + pics_ratio * pics_mean_method_call_nb * pics_mean_method_call_depth
        )
        # TODO: Should divide by the method size?
        return call_density

    def extract_call_densities(self, full_data: FullData):
        return self.extract_from_full_data(
            full_data=full_data, extraction_method=self.extract_run_call_density
        )

    # Mem accesses presence (aka how filled are the methods with memory accesses)
    # \______________________________________________________________________________

    def extract_mem_density(self, run_data: RunData, *args, **kwargs):
        tracing_data: TracingData = run_data["execution_data"]["emulation_data"][
            "tracing_data"
        ]
        instrs_nb: int = tracing_data["instrs_nb"]
        mem_instrs_nb: int = tracing_data["instrs_class"]["memory"]
        mem_density: float = mem_instrs_nb / instrs_nb * 100
        return mem_density

    def extract_mem_densities(self, full_data: FullData):
        return self.extract_from_full_data(
            full_data=full_data, extraction_method=self.extract_mem_density
        )

    # Extract Cycles
    # \________________

    def extract_cycle(self, run_data: RunData, *args, **kwargs):
        cycles_nb: int = run_data["execution_data"]["emulation_data"]["nb_cycles"]
        return cycles_nb

    def extract_cycles(self, full_data: FullData):
        return self.extract_from_full_data(
            full_data=full_data, extraction_method=self.extract_cycle
        )

    # Extract Cycles per instruction
    # \__________________________________

    def extract_cycle_per_instruction(self, run_data: RunData, *args, **kwargs):
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
                    # Extract method density
                    method_densities: List[float] = self.extract_method_densities(
                        full_data
                    )
                    # Extract call density
                    call_densities: List[float] = self.extract_call_densities(full_data)
                    # Extract cycle nb
                    nb_cycles: List[int] = self.extract_cycles(full_data)
                    # Extract CPI
                    cpis: List[float] = self.extract_cycles(full_data)
                    call_application_class_data: CallApplicationClassData = {
                        "name": str(call_app_path),
                        "isolation": isolation_type,
                        "method_densities": method_densities,
                        "call_densities": call_densities,
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
                    # Extract method density
                    method_densities: List[float] = self.extract_method_densities(
                        full_data
                    )
                    # Extract mem density
                    mem_densities: List[float] = self.extract_mem_densities(full_data)
                    # Extract cycle nb
                    nb_cycles: List[int] = self.extract_cycles(full_data)
                    # Extract CPI
                    cpis: List[float] = self.extract_cpis(full_data)
                    mem_application_class_data: MemoryApplicationClassData = {
                        "name": str(mem_app_path),
                        "isolation": isolation_type,
                        "method_densities": method_densities,
                        "mem_densities": mem_densities,
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
        for app_data in application_classes_data:
            ax.scatter(app_data["method_densities"], app_data["call_densities"])

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_xlabel("Method density")
        ax.set_ylabel("Call density")
        ax.set_title("Application classes with varying method size and call density")

    # Plot Memory Application Classes
    # \__________________________________

    def plot_mem_application_classes(
        self, ax: Axes, application_classes_data: List[MemoryApplicationClassData]
    ):
        for app_data in application_classes_data:
            ax.scatter(app_data["method_densities"], app_data["mem_densities"])

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_xlabel("Method density")
        ax.set_ylabel("Memory instruction density")
        ax.set_title("Application classes with varying method size and memory instruction density")

    # Plot Call Cycles
    # \___________________

    def plot_call_nb_cycles(
        self, ax, application_classes_data: List[CallApplicationClassData]
    ):
        for app_data in application_classes_data:
            ax.bar(mean(app_data["call_densities"]), mean(app_data["nb_cycles"]))

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_xlabel("Number of cycles")
        ax.set_ylabel("Call density")
        ax.set_title("Number of cycles with varying call density")

    # Plot Memory Cycles
    # \___________________

    def plot_mem_nb_cycles(
        self, ax, application_classes_data: List[MemoryApplicationClassData]
    ):
        for app_data in application_classes_data:
            ax.bar(mean(app_data["mem_densities"]), mean(app_data["nb_cycles"]))

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_xlabel("Number of cycles")
        ax.set_ylabel("Memory instruction density")
        ax.set_title("Number of cycles with varying memory instruction density")

    # Plot Call CPIs
    # \___________________

    def plot_call_cpis(
        self, ax, application_classes_data: List[CallApplicationClassData]
    ):
        for app_data in application_classes_data:
            ax.bar(mean(app_data["call_densities"]), mean(app_data["cpis"]))

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_xlabel("CPI")
        ax.set_ylabel("Call density")
        ax.set_title("CPIs with varying call density")

    # Plot Memory Cycles
    # \___________________

    def plot_mem_cpis(
        self, ax, application_classes_data: List[MemoryApplicationClassData]
    ):
        for app_data in application_classes_data:
            ax.bar(mean(app_data["mem_densities"]), mean(app_data["cpis"]))

        # ax.legend([app_data["name"] for app_data in application_classes_data])
        ax.set_xlabel("CPI")
        ax.set_ylabel("Memory instruction density")
        ax.set_title("CPIs with varying memory instruction density")


if __name__ == "__main__":
    _, axs = plt.subplots(3, 2)
    plotter = Plotter()
    call_application_classes: List[CallApplicationClassData] = plotter.process_call_application_classes(["no_isolation"])
    mem_application_classes: List[MemoryApplicationClassData] = plotter.process_mem_application_classes(["no_isolation"])
    plotter.plot_call_application_classes(axs[0, 0], call_application_classes)
    plotter.plot_mem_application_classes(axs[0, 1], mem_application_classes)
    plotter.plot_call_nb_cycles(axs[1, 0], call_application_classes)
    plotter.plot_mem_nb_cycles(axs[1, 1], mem_application_classes)
    plotter.plot_call_cpis(axs[2, 0], call_application_classes)
    plotter.plot_mem_cpis(axs[2, 1], mem_application_classes)
    plt.show()
