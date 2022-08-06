#   python clear_files.py

import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

os.system("rm -rf cpu_usage.txt")
os.system("rm -rf snort_alerts.txt")
os.system("rm -rf packets_in_time.txt")
os.system("rm -rf flow_stats_predict.txt")
os.system("rm -rf snort_alerts_time.txt")
os.system("rm -rf flow_stats_time.txt")
os.system("rm -rf evaluation_results.txt")

os.system("rm -rf *signature.txt")
os.system("rm -rf *anomaly.txt")
