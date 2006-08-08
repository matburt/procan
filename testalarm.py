#!/usr/bin/env python
import sys
import getopt

print "Alarm!\n"
f = open("/home/mat/projects/procan/alarmfile-"+sys.argv[2], 'w')
f.write("caught an alarm for: " + sys.argv[1] + " " + sys.argv[2] + " " + sys.argv[3] + " " + sys.argv[4] + "\n")
f.close

