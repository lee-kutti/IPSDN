#   python CPU_usage.py

import psutil 
import time 
import sys
import os
#get pid of running ryu-manager  
pid = psutil.Process(int(sys.argv[1]))

os.chdir(os.path.dirname(os.path.abspath(__file__)))

while True:
    cpu = pid.cpu_percent()
    monitor = open("Txt_Files/monitor.txt", "a+")
    monitor.write(str(cpu) + "\n")
    time.sleep(1)
    monitor.close()
