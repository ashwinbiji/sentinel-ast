from setuptools import setup

setup(
    name='sentinel-sast',
    version='1.0.0',
    description='Sentinel SAST & Automated Program Repair Platform',
    py_modules=['sentinel', 'parser_engine', 'cst_remediator'],
    install_requires=[
        'libcst',
    ],
    entry_points={
        'console_scripts': [
            'sentinel=sentinel:main',
        ],
    },
)