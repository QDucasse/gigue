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

  > in `src/instructions.py` and `src/method.py`

- **Parameter tuning:** A GUI and API to tune the parameters of generated code and methods.

  > in `src/gigue` and `src/gui`

- **Testing Infrastructure:** Using [Unicorn](https://github.com/unicorn-engine/unicorn) and [Capstone](https://github.com/capstone-engine/capstone) along with the developed disassembler to write all the tests in the`tests` folder.

  > in `src/disassembler` and `tests/*`



## Development

To run all the tests run:

```
tox
```



## License

```
BSD 2-Clause License

Copyright (c) 2022, Quentin Ducasse. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

