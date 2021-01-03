import pandas as pd


class Reader:
    def __init__(self, file_path: str):
        self.file_path = file_path

    def read_csv(self) -> pd.DataFrame:
        return pd.read_csv(self.file_path, header=["ip_address"])

    def read_txt(self) -> pd.DataFrame:
        return pd.read_csv(self.file_path, sep=",", header=["ip_address"])
