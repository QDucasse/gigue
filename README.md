# Gigue: Benchmark Setup and Code Generator for JIT code on RISC-V

[![GithubActions](https://github.com/qducasse/gigue/actions/workflows/github-actions.yml/badge.svg)](https://github.com/QDucasse/gigue/actions)

---

**Gigue** (*french for jitter*) consists of a machine code generator for RISC-V that mimics the execution of JIT code in concordance with an interpretation loop. The objective is to compare memory isolation memory on a simple model and easily (re-)generate the corresponding machine code parts for both the interpretation loop and JITed code. The base model generates an interpretation loop, a succession of calls to the JIT code. It generates a static binary with both binaries (interpretation loop and JIT elements) along with data the JIT elements use and basic OS facilities to run on top of the [Rocket CPU](https://github.com/chipsalliance/rocket-chip) (v1.5 version).

## Installation

The project was developed using [`pipenv`](https://github.com/pypa/pipenv) and Python 3.9. whose installation is presented below as well:

- *`pyenv` installation:*
```bash
# Install required library headers for pyenv
sudo apt-get install build-essential zlib1g-dev libffi-dev libssl-dev libbz2-dev libreadline-dev libsqlite3-dev liblzma-dev

# Install pyenv to manage Python versions
curl https://pyenv.run | bash

# Update PATH (append these to ~/.bashrc)
export PYENV_ROOT="$HOME/.pyenv"
command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
```

- *`pipenv` installation:*
```bash
# Install pip
sudo apt-get install python3-pip

# Install pipenv
pip install --user pipenv

# Update PATH (append these to ~/.bashrc)
export PIPENV_BIN="$HOME/.local/bin"
command -v pipenv >/dev/null || export PATH="$PIPENV_BIN:$PATH"
```

- *`gigue` installation:*
```bash
# Install gigue and its pipenv environment
git clone git@github.com:QDucasse/gigue.git
pipenv install
pipenv shell
```

## Gigue: CLI and Usage

Gigue supports three different usages and their corresponding CLIs: **Gigue** itself to generate one binary (and facilities to execute it), **Toccata** to generate several binaries, run them and extract information from the logs, and **Prelude** to display helper infos to implement custom instructions for toolchains/processors and generate minimal binaries containing these instructions.

### Gigue: Binary Generation and Execution

The binary generator CLI and its main arguments are the following (others are defined in [`gigue/cli.py`](https://github.com/QDucasse/gigue/blob/main/gigue/cli.py)):
```bash
# Binary generator CLI
python -m gigue -h
usage: __main__.py 
    [-h] [-s SEED] [-a INTADDR] [-j JITADDR] [-t] 
    [-i ISOLATION] [-js JITSIZE] [-n NBMETH] [--regs REGS]
    [-vm VARMETH] [-vs STDEVMETH] 
    [-cm CALLMEAN] [-cs CALLSTDEV] [-cdm CALLDEPTHMEAN] 
    [--datareg DATAREG] [--datasize DATASIZE] [--datagen DATAGEN] 
    [-r PICRATIO] [--picmeancase PICMEANCASE] [--piccmpreg PICCMPREG]
    [--pichitcasereg PICHITCASEREG] 
    [-oi OUTINT] [-oj OUTJIT] [-od OUTDATA]
```

The whole list is available below but the most important ones are:
 - **JIT size / methods number**: define the size of methods and the binary
 - **Method size variation parameters**: define the amount of variation in method size
 - **Call occupation parameters**: define the call occupation of methods
 - **PIC parameters**: define the outline of PICs and their presence

An example generation command would be:

```bash
python -m gigue 
    -js 1500 -n  25      # Will create 25 methods of size 60
    -vm 0.2  -vs 0.1     # Size variation of 20% (10% std dev)
    -cm 0.2  -cs 0.1     # Call occupation of 20% (10% std dev)
    -cdm 2               # Mean call depth of 2
    --isolation rimifull # Domain isolation / shadow stack
    --datagen   random   # 200 bytes of random data
    --datasize  1600     #            -
```

This generates the following files in the `bin/` directory:
 - `int.bin`: raw machine code of the interpretation loop (with trailing `nop`s)
 - `jit.bin`: raw machine code of the JIT code region
 - `data.bin`: raw machine code of the generated data (following the data generation strategy)

To create a running executable, the environment variable `RISCV` should be defined to point to a working RISC-V toolchain (*e.g.:* `export RISCV="/opt/riscv-rocket"`), the instructions to setup the one defined by Rocket are [here](https://github.com/chipsalliance/rocket-chip#setting-up-the-riscv-environment-variable). 

To run this executable, the environment variable `ROCKET` should be defined to point to the `rocket-chip` repository with a compiled emulator (*e.g.:* `export ROCKET="/path/to/rocket-chip"`). The instructions to compile the `emulator` are presented [here](https://github.com/chipsalliance/rocket-chip#building-the-project). 

To install the dependencies, follow this [guide](https://qducasse.github.io/posts/2023-01-27-rocket_installation/)

The [`Makefile`](https://github.com/QDucasse/gigue/blob/main/Makefile) then provides several commands:
- `make dump`: (default) generates the executable binary and the different dumps
  1. compiles the different bare OS helpers (in [`resources/common`](https://github.com/QDucasse/gigue/blob/main/resources/)).
  2. compiles the `gigue` binary using a template from [templates](https://github.com/QDucasse/gigue/blob/main/resources/templates)that loads `out.bin`, loads data address in a register, and puts the data right after. The templates vary to provide ways to set up security modules (PMP), or relax the structure for instruction unit tests. This template can be specified using `TEMPLATE=<template_name>` (presented below).
  3. links them all together using a slightly modified [linker script](https://github.com/QDucasse/gigue/blob/main/resources/test.ld) than the one provided in the Rocket tests suite to generate an `elf` file
  4. generates the dump of both the generated `gigue` binary alone (obtained by "forcing" a conversion using `obj-copy` before `obj-dump`) and the linked binary
- `make exec` runs the binary on top of the rocket emulator, default configuration is `DefaultConfig` but can be specified with *e.g.* `ROCKET_CONFIG=DefaultSmallConfig` and maximum test cycles with `ROCKET_MAX_CYCLES=10000000`.


For binaries, several templates are available that define additional subroutines for the binary. Among them:

- `base`: both sides of the JIT generation (interpreter and binary) along with a `.data` section
- `pmp`: `base` + a PMP config and setup
- `rimi`: `pmp` + DMP config and setup
- `unit`: includes unit tests examples as defined in `benchmarks/rocket_helper.py` 
- `unitrimi`: `unit` + PMP/DMP setup

By default, the template selected for Gigue is `base`/`rimi` and `unit`/`unitrimi` for unit tests. The template can be specified explicitely with for example:

```bash
make TEMPLATE=base
```

It is expecting the corresponding binaries (`int.bin`/`jit.bin` for base templates and `unit.bin` for unit tests).



### Toccata: Running Benchmarks

Gigue provides another CLI to generate, run and qualify binaries named Toccata. All scripts are defined in the [`toccata`](https://github.com/QDucasse/gigue/blob/main/toccata) section with the description of the data structures in [`data.py`](https://github.com/QDucasse/gigue/blob/main/toccata/data.py) and the main element, [`runner.py`](https://github.com/QDucasse/gigue/blob/main/toccata/runner.py). 

The runner will (1) generate a binary, (2) compile it, and (3) run it on the Rocket emulator. The CLI provides two ways of qualifying a runner configuration: 
- (1) using a `json` config and providing it with: 
```bash
python -m toccata config <your_file>.json
```
When using this method, a configuration file can be derived from the base one as defined in [`base_config.json`](https://github.com/QDucasse/gigue/blob/main/toccata/config/base_config.json):

```json
{
    "nb_runs": 1,
    "run_seeds": [],
    "input_data": {
        "uses_trampolines": 1,
        "isolation_solution": "none",
        "registers": [5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31],
        "weights": [25, 30, 10, 5, 10, 10, 10],
        "interpreter_start_address": 0, 
        "jit_start_address": 12288,
        "jit_size": 10000,
        "jit_nb_methods": 100,
        "method_variation_mean": 0.2,
        "method_variation_stdev": 0.1,
        "call_depth_mean": 2,
        "call_occupation_mean": 0.2,
        "call_occupation_stdev": 0.1,
        "pics_ratio": 0.2,
        "pics_mean_case_nb": 1,
        "pics_cmp_reg": 6,
        "pics_hit_case_reg": 5,
        "data_reg": 31,
        "data_size": 1600,
        "data_generation_strategy": "random",
        "rocket_input_data": {
            "rocket_config": "DefaultConfig",
            "rocket_max_cycles": 10000000
        }
    }
}
```
It involves the same arguments as the ones the gigue CLI uses and more metadata such as the seed or the isolation solution used.

- (2) using presets as defined in the CLI:
```bash
python -m toccata param -n low -c high --isolation rimifull
```
The following parameters are accessible (seen with `python -m toccata param -h`):
- `-r` the number of runs for a similar config
- `-n` the number of methods (low/medium/high)
- `-c` the call occupations (low/medium/high)
- `-m` the memory access intensities (low/medium/high)
- `-s` the seeds
- `-i` the isolation solution


---


For each method, the following actions are performed:
1. checks the environment variables (`RISCV` for the toolchain and `ROCKET` for the chip with the emulator compiled),
2. loads the configuration file,

(for each run)

3. generates the binary according to the input parameters,
4. parses the `elf` dump to extract the start address, end address and return address,
5. runs the binary on top of Rocket and extracts the number of cycles needed to run the binary,
6. stores the dumps and rocket logs for each run in the corresponding `toccata/results/<config_name>_<datetime>/<run_nb>` directory and the `data.json` in the parent directory.

> *Note:* each step contains a `<step>_ok` parameter that ensures the process went correctly (but does not stop the benchmark altogether).

### Prelude: Helper and Minimal Binaries

Prelude provides simple helpers to display the changes needed to integrate custom instructions in well-known cores/toolchains. The helper functions available are `rocket` and `gnu`, and can be accessed using:

```bash
python -m prelude helper <helper_name>
```

Prelude also generates binaries with a minimal number of instructions to unit test custom instructions. Each new instruction is defined with an example (list of instructions) inside a tutorial. For example:

```python
RIMI_TUTORIAL: Tutorial = Tutorial(
    examples=[
        # ==========================
        # load/stores:
        #    add value to check
        #    store value
        #    load value back
        # ==========================
        InstructionExample(
            ["lb1", "sb1"],
            [
                IInstruction.addi(rd=10, rs1=0, imm=0x12),
                RIMISInstruction.sb1(rs1=31, rs2=10, imm=0),
                RIMIIInstruction.lb1(rd=11, rs1=31, imm=0),
            ],
        ),
        ...
    ]
)
```

The same example is used for `lb1` and `sb1` as they load/store a value! The corresponding binary is generated using:

```bash
python -m prelude instr lb1 -t unit
```

> Note: `-t` chooses the template for the binary generation as presented earlier.


## Gigue code structure

The project consists of four main parts:

- **Instruction builder:** generates instructions as defined in the constants and instructions source files.

  > found in `constants.py` for the raw instruction data, `instructions.py` for instruction helpers, `builder.py` that defines static methods to generate both single instructions and machine code stubs (*e.g.* calls, switches, *etc.*)

- **JIT elements:** model for the methods and PICs contained in the JIT binary.

  > found in `method.py`, `pic.py` and `trampoline.py` for their respective classes

- **Generator:** the global element that obtains parameters and generates the corresponding binaries through the process of: *filling* the JIT code with elements, *generating* instructions inside them, *patching* these instructions with calls to other elements, *generating* the interpretation loop then *writing* the binary files.

  > found in `generator.py` for the main code and `cli.py` for argument passing.

- **Isolation Solutions:** each isolation solution redefines its `constants`, additional `builder` utilities and a dedicated `generator`.

  > found in their corresponding folders, *e.g.* `fixer` or `rimi`.

## Development

Additional dependencies are required to run the project tests through `pytest` and `tox` for different environments (systems/python versions) that will then be used in the CI:

```bash
# Install test dependencies
pipenv install --dev
# Launching the tests
pytest
# Running all test environments
tox
# Running the linters and type checker (do it before pushing!)
tox -e check
```

The CI uses `tox` to run the different tools on the code before running the tests for each environment defined in the GitHub actions. Tools used in the CI are:

- [`black`](https://github.com/psf/black), the code formatter
- [`ruff`](https://github.com/charliermarsh/ruff), the import sorter and linter
- [`mypy`](https://github.com/python/mypy), the type checker

Unit tests use [Unicorn](https://github.com/unicorn-engine/unicorn) as a CPU simulator and [Capstone](https://github.com/capstone-engine/capstone) as a disassembler (along with an inhouse disassembler).


## Parameters

The full list of the parameters defining Gigue and available through its CLI is the following:

|              Name           | Shortcut | Description | Default value |
|-----------------------------|----------|-------------|---------------|
|         Seed                |   `-s`   | Seed for generation replication           | `bytes_to_int(os.urandom(16))` |
| Interpreter start address   |   `-a`   | Start address for the interpretation loop | `0x0` |
| JIT start address           |   `-j`   | Start address for the JIT code region     | `0x2000` |
| Isolation solution          |   `-i`   | Chosen isolation setup                    | `none`   |
| Uses trampolines            |  `-not`  | Revokes the use of trampolines (prevents the usage of some isolation solutions) | `false` |
| JIT code region size        |   `-js`  | Size in bytes of the JIT code region                    | `1000` |
| Methods number              |   `-n`  | Number of methods in the JTI code region                    | `100` |
| Available registers     | `--regs`   | Usable registers for the generation | RISC-V Callee-saved registers |
| Method variation (variance) | `-vm` | Mean variation of method sizes (parameter of `TruncNorm` distribution law) | 0.2 |
| Method variation (standard deviation) | `-vs` | Standard deviation of the variation of method sizes (parameter of a `TruncNorm` distribution law) | 0.1 |
| Call occupation (variance) | `-cm` | Mean call occupation of methods (parameter of a `TruncNorm` distribution law) | 0.2 |
| Call occupation (standard deviation) | `-cs` | Standard deviation of the call occupation of methods (parameter of a `TruncNorm` distribution law) | 0.1 |
| Mean call depth  | `-cdm` | Mean of method call depths (parameter of a `Poisson` distribution law) | 2 |
| Data register  | `--datareg` | Register storing the data address for simple offset access | 31 (refers to `X31`) |
| Data size | `--datasize` | Size of the generated data | `8 * 200` |
| Data generation | `--datagen` | Data generation method (random, iterative, etc.) | `random` |
| PIC ratio | `-r` | Amount of PIC generated compared to simple methods | `0.2` |
| PIC case number | `--picmeancase` | Mean number of PIC cases (parameter of a `ZeroTruncPoisson` distribution law) (1) | 2 |
| PIC cmp register | `--piccmpreg` | Register used to compare the class register to the expected value in the PIC switch case | `X6` |
| PIC hit case register | `--pichitcasereg` | Class register | `X5` |
| Interpreter binary name | `-oi` | - | `int.bin` |
| JIT code binary name | `-oj` | - | `jit.bin` |
| Data binary name | `-od` | - | `data.bin` |


> (1) Note that the mean of a `ZeroTruncPoisson` distribution is not equal to its parameter but comes close to it as it becomes bigger.