#!/usr/bin/env python3
"""Generate the pacu.wiki "Module-Details" page from each module's module_info.

Walks pacu/modules/*/main.py, imports module_info from each, and renders
markdown grouped by category in the same format as the wiki's
Module-Details.md page. Used by .github/workflows/update-modules-wiki.yml
to keep that page in sync automatically; can also be run locally:

    poetry run python scripts/generate_module_wiki.py > /path/to/pacu.wiki/Module-Details.md
"""
import importlib
import sys
from pathlib import Path

MODULES_DIR = Path(__file__).resolve().parent.parent / 'pacu' / 'modules'


def iter_module_infos():
    for entry in sorted(MODULES_DIR.iterdir()):
        main_file = entry / 'main.py'
        if not entry.is_dir() or not main_file.exists():
            continue
        module = importlib.import_module(f'pacu.modules.{entry.name}.main')
        importlib.reload(module)
        yield module.module_info


def render(module_infos):
    by_category = {}
    for info in module_infos:
        by_category.setdefault(info['category'], []).append(info)

    lines = []
    for category in sorted(by_category):
        lines.append(f'## {category}')
        for info in sorted(by_category[category], key=lambda m: m['name']):
            description = ' '.join(info['description'].split())
            lines.append(f"### {info['name']}")
            lines.append(f"> **{info['one_liner']}**")
            lines.append('')
            lines.append(description)
            lines.append('')
            lines.append('')
    return '\n'.join(lines).rstrip() + '\n'


def main():
    sys.stdout.write(render(iter_module_infos()))


if __name__ == '__main__':
    main()
