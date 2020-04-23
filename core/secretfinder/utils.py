import math
import json
import re

class Color:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    # noinspection SpellCheckingInspection
    ENDC = '\033[0m'

    @staticmethod
    def print(color, text):
        print(f'{color}{text}{Color.ENDC}')


def shannon_entropy(data):
    if not data:
        return 0

    entropy = 0
    for character_i in range(256):
        px = data.count(chr(character_i)) / len(data)
        if px > 0:
            entropy += - px * math.log(px, 2)
    return entropy

def regex_checker(data):
    try:
        f = open('regexs.json', 'r')
        regexes = json.loads(f.read())
        results = {}
        for key in regexes:
            regex = re.compile(regexes[key])
            result = regex.findall(data)
            if result:
                results[key] = result
        return results

    except FileNotFoundError:
        return FileNotFoundError

def contains_secret(data, THRESHOLD=3.5):
    return shannon_entropy(data) > THRESHOLD
