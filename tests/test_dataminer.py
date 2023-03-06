import pytest

from gigue.dataminer import Dataminer
from gigue.helpers import align, bytes_to_int


def test_min_random():
    miner = Dataminer()
    data_bin = miner.mine_random(0)
    assert len(data_bin) == 8


@pytest.mark.parametrize("n", range(0, 8 * 20, 8))
def test_min_iterative32(n):
    miner = Dataminer()
    data_bin = miner.mine_iterative32(n)
    assert len(data_bin) == 8
    assert bytes_to_int(data_bin[:4]) == n // 4
    assert bytes_to_int(data_bin[4:]) == n // 4 + 1


@pytest.mark.parametrize("n", range(0, 8 * 20, 8))
def test_min_iterative64(n):
    miner = Dataminer()
    data_bin = miner.mine_iterative64(n)
    assert len(data_bin) == 8
    assert bytes_to_int(data_bin) == n // 8


@pytest.mark.parametrize("size", [8 * 3, 8 * 5, 8 * 20])
def test_generate_data_random(size):
    miner = Dataminer()
    data_bin = miner.generate_data(generation_strategy="random", size=size)
    assert len(data_bin) == align(size, 8)


@pytest.mark.parametrize("size", [8 * 3, 8 * 5, 8 * 20])
def test_generate_data_iterative32(size):
    miner = Dataminer()
    data_bin = miner.generate_data(generation_strategy="iterative32", size=size)
    size = align(size, 8)
    assert len(data_bin) == size
    for i in range(0, size, 8):
        assert bytes_to_int(data_bin[i : i + 4]) == i // 4


@pytest.mark.parametrize("size", [8 * 3, 8 * 5, 8 * 20])
def test_generate_data_iterative64(size):
    miner = Dataminer()
    data_bin = miner.generate_data(generation_strategy="iterative64", size=size)
    size = align(size, 8)
    assert len(data_bin) == size
    for i in range(0, size, 8):
        assert bytes_to_int(data_bin[i : i + 8]) == i // 8
