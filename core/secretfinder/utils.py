import math
import json
import re
import os

class Color:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    # noinspection SpellCheckingInspection
    ENDC = '\033[0m'

    @staticmethod
    def print(color, text):
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

def regex_checker(userdata):

    results = {}
    __location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

    try:
        f =open(os.path.join(__location__, 'regexs.json'))
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

def contains_secret(data, THRESHOLD=3.5):
    return shannon_entropy(data) > THRESHOLD
