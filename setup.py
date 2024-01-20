from setuptools import find_packages, setup

setup(
    name='foss_cryptography',
    packages=find_packages(include=['cryptography']),
    version='1.0.1',
    description='Elliptic Cryptography',
    author='Stefano',
    setup_requires=['pytest-runner'],
    tests_require=['pytest==4.4.1'],
    test_suite='tests',
)