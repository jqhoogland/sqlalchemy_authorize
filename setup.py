#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = []

test_requirements = ['pytest>=3', 'oso', 'sqlalchemy-oso']

setup(
    author="Jesse Hoogland",
    author_email='jesse@jessehoogland.com',
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    description="An unopinionated extension to enforce role-/relation-/attribute-based access control.",
    entry_points={
        'console_scripts': [
            'sqlalchemy_authorize=sqlalchemy_authorize.cli:main',
        ],
    },
    install_requires=requirements,
    license="MIT license",
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    keywords='sqlalchemy_authorize',
    name='sqlalchemy_authorize',
    packages=find_packages(include=['sqlalchemy_authorize', 'sqlalchemy_authorize.*']),
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/jqhoogland/sqlalchemy_authorize',
    version='0.1.0',
    zip_safe=False,
)
