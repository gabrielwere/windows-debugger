from ctypes import *
import time

count = 0;
msvcrt = cdll.msvcrt

while 1:
    msvcrt.printf(b"count is %d\n",count)
    count += 1
    time.sleep(2)