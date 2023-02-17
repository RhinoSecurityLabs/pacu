import zipfile
from pathlib import Path
from pacu.core.lib import pacu_dir
from pacu.utils import zip_file


def test_pacu_dir():
    assert str(pacu_dir()) == str(Path(__file__).parents[1]/'pacu')


def test_zip_file(tmp_path):
    ZIP_PATH = tmp_path/'test.zip'
    file_data = {
        'file01':'abc',
        'file02':'zxy'
    }
    zip_file(ZIP_PATH, file_data)

    assert ZIP_PATH.is_file()

    with zipfile.ZipFile(ZIP_PATH,"r") as zip_ref:
        zip_ref.extractall(tmp_path)
    assert (tmp_path/'file01').is_file()
    assert (tmp_path/'file02').is_file()

    with open(tmp_path/'file01') as f:
        assert file_data['file01'] == f.read()

    with open(tmp_path/'file02') as f:
        assert file_data['file02'] == f.read()
