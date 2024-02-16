#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from glob import glob
from os.path import basename, splitext

from setuptools import find_packages, setup

setup(
    name="gigue",
    version="0.1.0",
    license="BSD-2-Clause",
    description="Interpretation loop and JIT code generator for RISC-V",
    author="Quentin Ducasse",
    author_email="quentin.ducasse@ensta-bretagne.org",
    url="https://github.com/qducasse/gigue",
    packages=find_packages(),
    py_modules=[splitext(basename(path))[0] for path in glob("gigue/*.py")],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        # complete classifier list:
        # http://pypi.python.org/pypi?%3Aaction=list_classifiers
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: Unix",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Utilities",
    ],
    python_requires=">=3.10",
    install_requires=["capstone==5.0.0rc2", "unicorn==2.0.1.post1"],
    entry_points={
        "console_scripts": [
            "gigue = gigue.cli:main",
        ]
    },
)
