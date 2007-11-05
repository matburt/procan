#!/usr/bin/env python
# gnuplot procan plugin
# Written by:  Matthew W. Jones <matburt@oss-institute.org>
# Plugin Version: 0.2 (6/26/2006)
#
# - Pass no options to open a gnuplot window
# - or pass a first parameter as the full path to a postscript file.
#
import os
import sys
import string
import time
from Numeric import *
import Gnuplot, Gnuplot.funcutils

##Plot data into a window, keep the window open and update it whenever we get
##new data.
class pp_ContinuousPlot:
    def __init__(self, optpath=""):
	if len(optpath) > 1:
	    self.opt=optpath
	else:
	    self.opt=""
	self._plot = Gnuplot.Gnuplot();
	self.history = {}
	self.graphrange = {}
	self.procs = {}
	for i in range(0,24):
	    self.graphrange[i] = time.localtime()[3]+i
	    if self.graphrange[i] > 23:
		self.graphrange[i] = self.graphrange[i]-(time.localtime()[3]+1)
	
    ##Process input from procan on stdin
    def runLoop(self):
	while 1:
	    redir = sys.stdin.readline()
	    self.updateDisplay(sys.stdin.readline())
	    print redir
	    
    ##Redraw the gnuplot display with our current data.
    def updateDisplay(self, line):
	self.processLine(line)
	self.procs = {}
	#could eliminate this whole block by revising processLine
	for hour in self.history.keys():
	    for proc in self.history[hour].keys():
		if not self.procs.has_key(proc):
		    self.procs[proc] = {}
		self.procs[proc][hour] = self.history[hour][proc]
	
	#missing = []
	#for proc in self.procs.keys():
	#    for i in range(0,len(self.procs[proc])-1):
	#	for j in range(0,int(self.procs.keys()[i+1]) - int(self.procs.keys()[i])):
	#	    missing.append(self.procs.keys()[i]+j)
	#    for misshour in missing:
	#	self.procs[proc][misshour] = {}

	self.resetGraph()

	shouldreplot = False
	for proc in self.procs.keys():
	    for hour in self.procs[proc].keys():
		data = Gnuplot.Data([self.keyfromval(hour,self.graphrange),self.procs[proc][hour][1]],title=proc)
	    if not shouldreplot:
		self._plot.plot(data)
		shouldreplot = True
	    else:
		self._plot.replot(data)
	if self.opt != "":
	    self._plot.hardcopy(self.opt, enhanced=1, color=1)

    ##Parse the line recieved from ProcAn
    ##This is wrong because it doesn't reset the counter for each hour or is it??
    def processLine(self, line):
	if line[0] != "[":
	    return
	s_line = string.split(line,",")
	s_line[0] = s_line[0][1:len(s_line[0])]
	s_line[len(s_line)-1] = s_line[len(s_line)-1][0:len(s_line[len(s_line)-1])-1]
	if not self.history.has_key(time.localtime()[3]):
	    self.history[time.localtime()[3]] = {}
	lefthour = int(s_line[5][0:len(s_line[5])-1])
	if self.procs.has_key(s_line[1]):
	    for eachhour in self.procs[s_line[1]]:
		lefthour = lefthour-int(self.procs[s_line[1]][eachhour][1])
	
	if self.history[time.localtime()[3]].has_key(s_line[1]):
	    self.history[time.localtime()[3]][s_line[1]][0] = int(self.history[time.localtime()[3]][s_line[1]][0])+1
	    self.history[time.localtime()[3]][s_line[1]][1] = self.history[time.localtime()[3]][s_line[1]][1]+lefthour #int(s_line[5][0:len(s_line[5])-1])
	else:
	    self.history[time.localtime()[3]][s_line[1]] = [1,lefthour]#int(s_line[5][0:len(s_line[5])-1])]

    ##Perform a full reset on the plot.
    def resetGraph(self):
	self._plot.reset()
	self._plot('set xrange [0:24]')
	self._plot('set yrange [0:20]')
	self._plot('set data style linespoints')
	self._plot.title("ProcAn")
	self._plot.xlabel("Hour")
	self._plot.ylabel("Level of Interests")


    ##Helper method to retrieve a key
    def keyfromval(self,val,dict):
	for key in dict.keys():
	    if dict[key] == val:
		return key
	return ""


if __name__ == '__main__':
    #Handle Arguments
    if len(sys.argv) > 1:
	print "Writing PostScript file: " + str(sys.argv[1])
	cp = pp_ContinuousPlot(sys.argv[1])
	cp.runLoop()
    else:
	cp = pp_ContinuousPlot()
	cp.runLoop()
