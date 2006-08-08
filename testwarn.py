#!/usr/bin/env python
import sys
import getopt

print "Warning!\n"
f = open("/home/mat/projects/procan/warnfile-"+sys.argv[2], 'w')
f.write("caught a warning for: " + sys.argv[1] + " " + sys.argv[2] + " " + sys.argv[3] + " " + sys.argv[4] + "\n")
f.close

