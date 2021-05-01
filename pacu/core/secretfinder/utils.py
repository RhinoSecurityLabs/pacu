import math
import json
import re
import os
from typing import Dict, Any

from pathlib import Path


class Color:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    # noinspection SpellCheckingInspection
    ENDC = '\033[0m'

    @staticmethod
    def print(color, text) -> None:
        print('{}{}{}'.format(color, text, Color.ENDC))


def shannon_entropy(data):
    if not data:
        return 0

    entropy = 0
    for character_i in range(256):
        px = data.count(chr(character_i)) / len(data)
        if px > 0:
            entropy += - px * math.log(px, 2)
    return entropy


def regex_checker(userdata) -> Dict[Any, list]:
    results = {}

    try:
        f = open(Path(__file__).parent/'regexs.json')
        data = f.read()
        regexs = json.loads(data)

        for key in regexs:
            regex = re.compile(regexs[key])
            result = regex.findall(userdata)

            if result:
                results[key] = result

    except Exception as e:
        raise e

    f.close()

    return results


def contains_secret(data, THRESHOLD=3.5) -> bool:
    return shannon_entropy(data) > THRESHOLD
