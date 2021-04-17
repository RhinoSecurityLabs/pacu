import setuptools
from pathlib import Path

with open("README.md", "r") as fh:
    long_description = fh.read()


requirements = Path('requirements.txt').read_text().splitlines()
test_requirements = Path('requirements-dev.txt').read_text().splitlines()


setuptools.setup(
    name="pacu",
    keywords='pacu',
    version="0.1.0",
    author="Ryan Gerstenkorn",
    author_email="ryan.gerstenkorn@rhinosecuritylabs.com",
    description="AWS exploitation framework, designed for testing the security of Amazon Web Services environments.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/RhinoSecurityLabs/pacu",
    packages=setuptools.find_packages(include=['pacu', 'pacu.*']),
    entry_points = {
        'console_scripts': ['pacu=pacu.__main__:main'],
    },
    install_requires=requirements,
    extras_require={
        "dsnap":  ["dsnap>=1.0.0"],
    },
    tests_require=test_requirements,
    classifiers=(
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Natural Language :: English',
        'Topic :: Security',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ),
)
