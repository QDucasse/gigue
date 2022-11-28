# Gigue: Benchmark Setup and Code Generator for JIT code on RISC-V

[![GithubActions](https://github.com/qducasse/gigue/actions/workflows/github-actions.yml/badge.svg)](https://github.com/QDucasse/gigue/actions)

---

## Installation

```
pip install gigue
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

> Note: a RISC-V compilation toolchain needs to be installed

Once the binaries are generated in the `bin/` directory, they can be transformed to ELF files using:
```
riscv64-unknown-linux-gnu-objcopy --input-target=binary --output-target=elf32-little jit.bin jit.elf
riscv64-unknown-linux-gnu-readelf -a jit.elf  
```

They can be disassembled with either of the following:
```
riscv64-unknown-linux-gnu-objdump -m riscv -b binary --adjust-vma=0x1000 -D jit.out
riscv64-unknown-linux-gnu-objdump -m riscv  --adjust-vma=0x1000 -D jit.elf
```


## Development

To run all the tests run:

```
tox
```

To run only one tox environment (e.g. `check`) run:
```
tox -e check
```