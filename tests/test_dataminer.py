import pytest

from gigue.dataminer import Dataminer
from gigue.helpers import bytes_to_int

DEFAULT_SIZE = 100


@pytest.mark.parametrize("size", [100, 101, 104, 108])
def test_initialization(size):
    miner = Dataminer(size)
    assert miner.size == (size // 8) * 8


def test_min_random():
    miner = Dataminer(DEFAULT_SIZE)
    data_bin = miner.mine_random(0)
    assert len(data_bin) == 8


@pytest.mark.parametrize("n", range(0, 8 * 20, 8))
def test_min_iterative32(n):
    miner = Dataminer(DEFAULT_SIZE)
    data_bin = miner.mine_iterative32(n)
    assert len(data_bin) == 8
    assert bytes_to_int(data_bin[:4]) == n // 4
    assert bytes_to_int(data_bin[4:]) == n // 4 + 1


@pytest.mark.parametrize("n", range(0, 8 * 20, 8))
def test_min_iterative64(n):
    miner = Dataminer(DEFAULT_SIZE)
    data_bin = miner.mine_iterative64(n)
    assert len(data_bin) == 8
    assert bytes_to_int(data_bin) == n // 8


@pytest.mark.parametrize("size", [8 * 3, 8 * 5, 8 * 20])
def test_generate_data_random(size):
    miner = Dataminer(size)
    data_bin = miner.generate_data("random")
    assert len(data_bin) == size


@pytest.mark.parametrize("size", [8 * 3, 8 * 5, 8 * 20])
def test_generate_data_iterative32(size):
    miner = Dataminer(size)
    data_bin = miner.generate_data("iterative32")
    assert len(data_bin) == size
    for i in range(0, miner.size, 4):
        assert bytes_to_int(data_bin[i : i + 4]) == i // 4


@pytest.mark.parametrize("size", [8 * 3, 8 * 5, 8 * 20])
def test_generate_data_iterative64(size):
    miner = Dataminer(size)
    data_bin = miner.generate_data("iterative64")
    assert len(data_bin) == size
    for i in range(0, miner.size, 8):
        assert bytes_to_int(data_bin[i : i + 8]) == i // 8
