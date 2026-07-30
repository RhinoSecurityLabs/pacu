import importlib.util
from pathlib import Path

SCRIPT_PATH = Path(__file__).parents[1] / 'scripts' / 'generate_module_wiki.py'
_spec = importlib.util.spec_from_file_location('generate_module_wiki', SCRIPT_PATH)
generate_module_wiki = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(generate_module_wiki)


def test_render_sorts_categories_and_modules_alphabetically():
    module_infos = [
        {'name': 'zzz__enum', 'category': 'ENUM', 'one_liner': 'Z one liner', 'description': 'Z description.'},
        {'name': 'aaa__enum', 'category': 'ENUM', 'one_liner': 'A one liner', 'description': 'A description.'},
        {'name': 'bbb__exfil', 'category': 'EXFIL', 'one_liner': 'B one liner', 'description': 'B description.'},
    ]

    output = generate_module_wiki.render(module_infos)

    assert output.index('## ENUM') < output.index('## EXFIL')
    assert output.index('### aaa__enum') < output.index('### zzz__enum')


def test_render_normalizes_multiline_description_whitespace():
    module_infos = [
        {
            'name': 'aaa__enum',
            'category': 'ENUM',
            'one_liner': 'One liner.',
            'description': '  This description\n   spans multiple\nlines.  ',
        },
    ]

    output = generate_module_wiki.render(module_infos)

    assert 'This description spans multiple lines.' in output


def test_render_ends_with_single_trailing_newline():
    module_infos = [
        {'name': 'aaa__enum', 'category': 'ENUM', 'one_liner': 'One liner.', 'description': 'Description.'},
    ]

    output = generate_module_wiki.render(module_infos)

    assert output.endswith('\n')
    assert not output.endswith('\n\n')
