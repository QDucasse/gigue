# Gigue: Benchmark Setup and Code Generator for JIT code on RISC-V

[![GithubActions](https://github.com/qducasse/gigue/actions/workflows/github-actions.yml/badge.svg)](https://github.com/QDucasse/gigue/actions)

---

## Installation

The project was developed using `pipenv` and Python 3.9. It can be installed with:

```bash
# Install required library headers for pyenv
sudo apt-get install build-essential zlib1g-dev libffi-dev libssl-dev libbz2-dev libreadline-dev libsqlite3-dev liblzma-dev

# Install pyenv to manage Python versions
curl https://pyenv.run | bash

# Update PATH (append these to ~/.bashrc)
export PYENV_ROOT="$HOME/.pyenv"
command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"

# Install pip
sudo apt-get install python3-pip

# Install pipenv
pip install --user pipenv

# Update PATH (append these to ~/.bashrc)
export PIPENV_BIN="$HOME/.local/bin"
command -v pipenv >/dev/null || export PATH="$PIPENV_BIN:$PATH"
```

## Usage

```bash
# One binary can be generated with
python -m gigue 
# A full run using a configuration in benchmarks/config/
python -m benchmarks default  # for default.json config
```

## Documentation

Gigue (*french for jitter*) consists of a machine code generator for RISC-V that mimics the execution of JIT code in concordance with an interpretation loop. The objective is to compare memory isolation memory on a simple model and easily (re-)generate the corresponding machine code parts for both the interpretation loop and JITed code. Parameters that can be tuned through a simple API/GUI are:

- number of JITed methods
- size of the JITed methods
- presence of polymorphic inline caches (PICs)
- number of cases per PIC
- ...

The project consists of three main parts:

- **Instruction generator:** An random instruction and method builder to generate RISC-V instructions.

  > in `src/instructions.py`, `src/method.py` and `src/generator.py`

- **Parameter tuning:** A GUI and API to tune the parameters of generated code and methods.

  > in `src/gigue` and `src/gui.py`

- **Testing Infrastructure:** Using [Unicorn](https://github.com/unicorn-engine/unicorn) and [Capstone](https://github.com/capstone-engine/capstone) along with the developed disassembler to write all the tests in the`tests` folder.

  > in `src/disassembler.py` and `tests/*`


## Binary Generation

> Note: a RISC-V compilation toolchain needs to be installed. This tool was developed in a project using the toolchain available in [rocket-tools](https://github.com/chipsalliance/rocket-tools).

DOC WIP

<!-- Once the binaries are generated in the `bin/` directory, they can be transformed to ELF files using:
```bash
$ riscv64-unknown-linux-gnu-objcopy --input-target=binary --output-target=elf32-little jit.bin jit.elf
$ riscv64-unknown-linux-gnu-readelf -a jit.elf  
```

They can be disassembled with either of the following:
```bash
$ riscv64-unknown-linux-gnu-objdump -m riscv -b binary --adjust-vma=0x1000 -D jit.elf
$ riscv64-unknown-linux-gnu-objdump -m riscv  --adjust-vma=0x1000 -D jit.elf
``` -->


## Development

To run all the tests on all environments or specific ones, run:
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
