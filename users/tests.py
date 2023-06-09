import pandas as pd

a = {"a": [1, 2, 3, 4, 5, 6], "b": [3, 4, 5, 6, 7, 8]}
df = pd.DataFrame(a)
df.to_csv("output.csv", index=False)
