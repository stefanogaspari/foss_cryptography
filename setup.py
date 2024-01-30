from setuptools import find_packages, setup

with open("README.md") as file:
    long_description = file.read()

setup(
    name='foss_cryptography',
    packages=find_packages(include=['cryptography']),
    version='2.0.1',
    url='https://github.com/stefanogaspari/foss_cryptography',
    description='Elliptic Cryptography and ECDSA',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Stefano Gaspari',
    setup_requires=['pytest-runner'],
    tests_require=['pytest==4.4.1'],
    test_suite='tests',
)