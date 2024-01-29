from setuptools import setup, find_packages
from os import path


def read(fname):
    return open(path.join(path.dirname(__file__), fname)).read()


setup(
    name='pymsf',
    author='ACCISA',
    version='0.0.1',
    packages=find_packages(),
    description='An additional abstract layer to the python metasploit rpc.',
    install_requires=[
        'pymetasploit3'
    ],
)
