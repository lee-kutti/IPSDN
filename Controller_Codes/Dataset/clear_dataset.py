#   python clear_dataset.py

import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

os.system("rm -rf ./*.csv")