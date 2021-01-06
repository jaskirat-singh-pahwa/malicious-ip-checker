from typing import List
from src.ip_checker.args import parse_args


def given_args() -> List[str]:
    return [
        "--ip-addresses", "test-path/for/ip-addresses",
        "--output-path", "test-path/to/save-output"
    ]


def test_args():
    args = parse_args(given_args())

    assert args == {
        "ip_addresses": "test-path/for/ip-addresses",
        "output_path": "test-path/to/save-output"
    }
