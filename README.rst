========
Overview
========

.. start-badges

.. list-table::
    :stub-columns: 1

    * - tests
      - | |github-actions| |requires|
        | |codecov|
    * - package
      - | |commits-since|

.. |github-actions| image:: https://github.com/qducasse/gigue/actions/workflows/github-actions.yml/badge.svg
    :alt: GitHub Actions Build Status
    :target: https://github.com/qducasse/gigue/actions

.. |requires| image:: https://requires.io/github/qducasse/gigue/requirements.svg?branch=main
    :alt: Requirements Status
    :target: https://requires.io/github/qducasse/gigue/requirements/?branch=main

.. |codecov| image:: https://codecov.io/gh/qducasse/gigue/branch/main/graphs/badge.svg?branch=main
    :alt: Coverage Status
    :target: https://codecov.io/github/qducasse/gigue

.. |commits-since| image:: https://img.shields.io/github/commits-since/qducasse/gigue/v0.0.0.svg
    :alt: Commits since latest release
    :target: https://github.com/qducasse/gigue/compare/v0.0.0...main



.. end-badges

Interpretation loop and JIT code generator for RISC-V

* Free software: BSD 2-Clause License

Installation
============

::

    pip install gigue

You can also install the in-development version with::

    pip install https://github.com/qducasse/gigue/archive/main.zip


Documentation
=============


To use the project:

.. code-block:: python

    import gigue
    gigue.longest()


Development
===========

To run all the tests run::

    tox

Note, to combine the coverage data from all the tox environments run:

.. list-table::
    :widths: 10 90
    :stub-columns: 1

    - - Windows
      - ::

            set PYTEST_ADDOPTS=--cov-append
            tox

    - - Other
      - ::

            PYTEST_ADDOPTS=--cov-append tox
