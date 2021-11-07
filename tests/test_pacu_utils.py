from pathlib import Path

from pacu.core.lib import pacu_dir


def test_pacu_dir():
    assert str(pacu_dir()) == str(Path(__file__).parents[1] / "pacu")
