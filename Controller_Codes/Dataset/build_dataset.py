#   python build_dataset.py

from ast import Index
import sys
import os
import pandas as pd

os.chdir(os.path.dirname(os.path.abspath(__file__)))
#os.system("rm -rf ./*.csv")

df_normal = pd.read_csv('../Txt_Files/flow_stats_normal.txt', index_col=False)
df_normal.columns = ['datapath_id', 'eth_src', 'duration', 'ip-protocol',
              'src-port', 'dst-port', 'byte-count', 'packet-count', 'class']

df_normal = df_normal.drop(['datapath_id', 'eth_src'], axis=1)

df_attack = pd.read_csv('../Txt_Files/flow_stats_attack.txt', index_col=False)
df_attack.columns = ['datapath_id', 'eth_src', 'duration', 'ip-protocol',
              'src-port', 'dst-port', 'byte-count', 'packet-count', 'class']

df_attack = df_attack.drop(['datapath_id', 'eth_src'], axis=1)

### testing
#df_normal = df_normal.drop(['src-port', 'dst-port'], axis=1)
#df_attack = df_attack.drop(['src-port', 'dst-port'], axis=1)
# df_normal = df_normal.drop(['byte-count'], axis=1)
# df_attack = df_attack.drop(['byte-count'], axis=1)
df_attack = df_attack.sample(frac = 0.6)
### testing


df_normal_train = df_normal.sample(frac=0.7)
df_normal_test = df_normal.drop(df_normal_train.index)

df_attack_train = df_attack.sample(frac=0.7)
df_attack_test = df_attack.drop(df_attack_train.index)

train_df = pd.concat([df_normal_train, df_attack_train])
test_df = pd.concat([df_normal_test, df_attack_test])

train_df = train_df.sample(frac = 1)
test_df = test_df.sample(frac = 1)


# train_df.to_csv('train_dataset.csv', index=False)
# test_df.to_csv('test_dataset.csv', index=False)

train_df.to_csv('train_dataset_with-src-dst-port.csv', index=False)
test_df.to_csv('test_dataset_with-src-dst-port.csv', index=False)

