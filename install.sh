#!/bin/bash

check_python_version() {
    echo "[ + ] Checking Python version . . ."
    echo "[ $ ] python3 --version"

    MINIMUM_VERSION="3.5"
    PYTHON_VERSION=$(python3 --version 2>&1)

    echo "$PYTHON_VERSION"

    # This ensures the Python version is 3.5 or higher. https://regex101.com/
    VERSION_REGEX="^Python\ ((3\.[^0-4])|(3\.[1-9][0-9]+)|([4-9]+\.\d+))(.*)$"

    if [[ $PYTHON_VERSION =~ $VERSION_REGEX ]]; then
        echo "[ + ] Your Python version is compatible with Pacu."
    else
        echo "\\033[38;5;202m[ - ] Pacu requires Python to be installed at version $MINIMUM_VERSION or higher. Your version is: $PYTHON_VERSION"
        echo "Please install Python version $MINIMUM_VERSION or higher. \\033[38;5;33mhttps://www.python.org/downloads/\\033[38;5;00m"
        exit 1
    fi
}

install_pip_requirements() {
    echo "[ + ] Installing Pacu's Python package dependencies . . ."
    echo "[ $ ] pip3 install -r requirements.txt"

    PIP_OUTPUT=$(pip3 install -r requirements.txt)
    PIP_ERROR_CODE=$?

    echo "$PIP_OUTPUT"

    if [ $PIP_ERROR_CODE = '0' ]; then
        echo "[ + ] Pip install finished. (exit $PIP_ERROR_CODE)"
    else
        echo "\\033[38;5;202m[ - ] Pip raised an error while installing Pacu's Python package dependencies."
        echo "All Python packages used by Pacu should be installed before pacu.py is run."
        echo "It may be helpful to try running \`pip install -r requirements.txt\` directly."
        echo "For assistance troubleshooting pip installation problems, please provide the"
        echo "developers with as much information about this error as possible, including all"
        echo "text output by install.sh. (exit $PIP_ERROR_CODE)\\033[38;5;00m"
        exit 1
    fi
}

check_python_version
install_pip_requirements
