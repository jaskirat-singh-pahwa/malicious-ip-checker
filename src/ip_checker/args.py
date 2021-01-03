from argparse import ArgumentParser
from typing import List, Dict


def parse_args(input_args: List) -> Dict[str]:
    parser = ArgumentParser()
    parser.add_argument("--ips", required=True)
    parser.add_argument("--output-path", required=True)

    return vars(parser.parse_args(input_args))

