from gigue.cli import main


def test_main_default():
    assert main([]) == 0
