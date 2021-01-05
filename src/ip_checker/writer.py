import pandas as pd


class Writer:
    def __init__(self, df: pd.DataFrame, write_path: str):
        self.df = df
        self.write_path = write_path

    def write_to_csv(self):
        self.df.to_csv(self.write_path)
