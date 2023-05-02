# Gigue: Benchmark Setup and Code Generator for JIT code on RISC-V

[![GithubActions](https://github.com/qducasse/gigue/actions/workflows/github-actions.yml/badge.svg)](https://github.com/QDucasse/gigue/actions)

---

**Gigue** (*french for jitter*) consists of a machine code generator for RISC-V that mimics the execution of JIT code in concordance with an interpretation loop. The objective is to compare memory isolation memory on a simple model and easily (re-)generate the corresponding machine code parts for both the interpretation loop and JITed code. The base model generates an interpretation loop, a succession of calls to the JIT code. It generates a static binary with both binaries (interpretation loop and JIT elements) along with data the JIT elements use and basic OS facilities to run on top of the [Rocket CPU](https://github.com/chipsalliance/rocket-chip).

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

## CLI and Usage

Gigue provides two different CLIs: one to generate one binary (and facilities to execute it) and another to generate several binaries, run them and extract information from the logs.

### Binary Generation and Execution

The binary generator CLI and its main arguments are the following (others are defined in [`gigue/cli.py`](https://github.com/QDucasse/gigue/blob/main/gigue/cli.py)):
```bash
# Binary generator CLI
python -m gigue -h
usage: python -m gigue [-h] [-S SEED] [-T] [--isolation ISOLATION] [-I INTADDR] [-J JITADDR] [-N NBELT]  [--datasize DATASIZE] [--datagen DATAGEN] [-M METMAXSIZE] [--maxcallnb MAXCALLNB] [--maxcalldepth MAXCALLDEPTH] [-R PICRATIO] [-P PICMETMAXSIZE] [--picmaxcases PICMAXCASES] [--piccmpreg PICCMPREG]

Gigue, JIT code generator

optional arguments:
  -h, --help            show this help message and exit
  -S SEED, --seed SEED  Start address of the interpretation loop
  -T, --uses_trampolines
                        Uses trampoline for calls/returns
  --isolation ISOLATION
                        Isolation solution to protect the binary (none, fixer, rimiss, rimifull)
  -I INTADDR, --intaddr INTADDR
                        Start address of the interpretation loop
  -J JITADDR, --jitaddr JITADDR
                        Start address of the JIT code
  -N NBELT, --nbelt NBELT
                        Number of JIT code elements (methods/pics)
  --datasize DATASIZE   Size of the data section
  --datagen DATAGEN     Data generation strategy
  -M METMAXSIZE, --metmaxsize METMAXSIZE
                        Maximum size of a method (in nb of instructions)
  --maxcallnb MAXCALLNB
                        Maximum calls in a method
  --maxcalldepth MAXCALLDEPTH
                        Maximum call depth of a method (i.e. nested calls)
  -R PICRATIO, --picratio PICRATIO
                        PIC to method ratio
  -P PICMETMAXSIZE, --picmetmaxsize PICMETMAXSIZE
                        PIC methods max size
  --picmaxcases PICMAXCASES
                        PIC max number of cases
```

An example generation command would be:

```bash
python -m gigue -T -N 100 -M 50 -R 0.5 --datasize 2048
```

This generates the following files in the `bin/` directory:
 - `out.bin`: raw machine code of the interpretation loop and JIT elements stitched together with `nop`s
 - `data.bin`: raw machine code of the generated data (following the data generation strategy)

To create a running executable, the environment variable `RISCV` should be defined to point to a working RISC-V toolchain (*e.g.:* `export RISCV="/opt/riscv-rocket"`), the instructions to setup the one defined by Rocket are [here](https://github.com/chipsalliance/rocket-chip#setting-up-the-riscv-environment-variable). 

To run this executable, the environment variable `ROCKET` should be defined to point to the `rocket-chip` repository with a compiled emulator (*e.g.:* `export ROCKET="/path/to/rocket-chip"`). The instructions to compile the `emulator` are presented [here](https://github.com/chipsalliance/rocket-chip#building-the-project). 

To install the dependencies, follow this [guide](https://qducasse.github.io/posts/2023-01-27-rocket_installation/)

The [`Makefile`](https://github.com/QDucasse/gigue/blob/main/Makefile) then provides several commands:
- `make dump`: (default) generates the executable binary and the different dumps
  1. compiles the different bare OS helpers (in [`resources/common`](https://github.com/QDucasse/gigue/blob/main/resources/)).
  2. compiles the `gigue` binary using the [`template.S`](https://github.com/QDucasse/gigue/blob/main/resources/template.S)that loads `out.bin`, loads data address in a register and puts the data right after.
  3. links them all together using a slightly modified [linker script](https://github.com/QDucasse/gigue/blob/main/resources/test.ld) than the one provided in the Rocket tests suite to generate an `elf` file
  4. generates the dump of both the generated `gigue` binary alone (obtained by "forcing" a conversion using `obj-copy` before `obj-dump`) and the linked binary
- `make exec` runs the binary on top of the rocket emulator, default configuration is `DefaultConfig` but can be specified with *e.g.* `ROCKET_CONFIG=SmallConfig` and maximum test cycless with `ROCKET_MAX_CYCLES=10000000`.

TODO: Expand on the execution model

### Running Benchmarks

Gigue provides a script to generate, run and qualify binaries. All scripts are defined in the [`benchmarks`](https://github.com/QDucasse/gigue/blob/main/benchmarks) with the description of the data structures in [`data.py`](https://github.com/QDucasse/gigue/blob/main/benchmarks/data.py) and the main element, [`runner.py`](https://github.com/QDucasse/gigue/blob/main/benchmarks/runner.py). 

The runner uses a `json` configuration file that should be added in the `benchmarks/config/` directory). The `default.json` contains:

```json
{
    "nb_runs": 3,
    "input_data": {
        "uses_trampolines": 0,
        "isolation_solution": "none",
        "seed": 0,
        "interpreter_start_address": 0, 
        "jit_start_address": 8192,
        "jit_elements_nb": 100,
        "registers": [5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31],
        "data_reg": 31,
        "data_size": 1600,
        "data_generation_strategy": "random",
        "method_max_size": 50,
        "max_call_depth": 5,
        "max_call_nb": 5,
        "pics_ratio": 0.2,
        "pics_method_max_size": 25,
        "pics_max_cases": 5,
        "pics_cmp_reg": 6,
        "pics_hit_case_reg": 5,
        "rocket_config": "DefaultConfig",
        "rocket_max_cycles": 100000000
    }
}
```

It involves the same arguments as the ones the gigue CLI uses and more metadata such as the seed or the isolation solution used.

Launching the `runner` through the command line is done with:

```bash
python -m benchmarks default  # for default.json config
```

This performs the following actions:
1. checks the environment variables (`RISCV` for the toolchain and `ROCKET` for the chip with the emulator compiled),
2. loads the configuration file,

(for each run)

3. generates the binary according to the input parameters,
4. parses the `elf` dump to extract the start address, end address and return address,
5. runs the binary on top of Rocket and extracts the number of cycles needed to run the binary,
6. stores the dumps and rocket logs for each run in the corresponding `benchmarks/results/<config_name>_<datetime>/<run_nb>` directory and the `data.json` in the parent directory.

> *Note:* each step contains a `<step>_ok` parameter that ensures the process went correctly (but does not stop the benchmark altogether).

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