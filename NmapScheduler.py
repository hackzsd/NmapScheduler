#!/usr/bin/env python
# Date: 26/01/2016 04:18 AM

__author__ = "Sahil Dhar"
__program_name__ = "Nmap Scheduler"


import Queue
import json
import os.path
import sys
import getopt
import subprocess
import threading

from re import findall,sub
from signal import signal,SIGINT
from datetime import datetime,date,time
from time import sleep
from os import _exit,getcwd
from subprocess import PIPE

class Scheduler:

	now = False

	def __init__(self, ip_file, verbose_option=False, config=None):
		
		cwd = getcwd().replace("\\","/")
		self.verbose_info = verbose_option 
		self.scheduled_time = datetime.now()
		self.config = {}

		self.ip_file = open(cwd+"/"+ip_file,"r+").read().split("\n")
		self.verbose('Targets: %s'%(" ".join(ip for ip in self.ip_file)))
		config_file = cwd+"/config.json"
	
		if os.path.exists(config_file):
			try:
				self.config = json.loads(open(config_file,"r").read())
				y = self.config["date"]['y']
				m = self.config["date"]['m']
				d = self.config["date"]['d']
				h = self.config["time"]['h']
				mi = self.config["time"]['m']
				self.scheduled_time = datetime.combine(date(y,m,d),time(h,mi))
				if self.scheduled_time < datetime.now():
					self.error("Scheduled Time Cannot be past time")
					self.exit()

			except Exception,ex:
				self.error("Some Exception Occurred : %s" %(str(ex)))

			self.verbose("Validating nmap command from config file")
			
			if len(findall(r'(\[.*?\])',self.config["command"])) == 2:
				self.verbose("Command fields validated")
			else:
				self.error("Unable to found [IP] fields in command")
				self.exit()
			
			print "Nmap Scheduler Successfully Configired to run at %s" %(self.scheduled_time)		

		else:
			self.config["command"] = "nmap -Pn -sS -sU -sT -T4 -vvvv -n -p- -O -sC [ip] -oA [ip]"
			self.config["threads"] = 2
			self.error("Unable to find config file, using default command\n\tNmap: %s" %(self.config["command"]))
			self.now = True

	def run_process(self, ip_list):
		while not ip_list.empty():
			ip = ip_list.get(timeout = 1)
			print "[+] Scanning started for  %s " %(ip)
			command = sub(r'\[.*?\]',ip,self.config["command"])
			self.verbose(command)
			p = subprocess.Popen(command,shell=True,stdout=PIPE)
			while p.returncode == None:	# Poking process :) for completion of task assigned			
				p.poll()
				sleep(1)
			print "Scanning Completed for ip : %s" %(ip)
				


	def verbose(self,msg):
		if self.verbose_info:
			print "[Info] "+msg
		else:
			pass

	def error(self,msg):
		print "[Error] "+msg

	def exit(self):
		self.kill_threads()
		_exit(0)

	def sig_handler(self,signum,frame):
		print "[+] CTRL + C Detected\n[!] Exiting"
		self.exit()

	def kill_threads(self):
		self.verbose("Killing Open Threads...")
		for th in threading.enumerate():
			if th != threading.current_thread():
				th.join()

	def start_scheduler(self):
		if not self.now:
			while datetime.now() < self.scheduled_time:
				sleep(1)
			print "[+] Starting Scheduler..."		
			q = Queue.Queue()
			for ip in set(self.ip_file):
				if ip != "":
					q.put(ip)

			for i in range(0,int(self.config["threads"])):
				threading.Thread(target=self.run_process,args=(q,)).start()
				
		else:
			print "[+] Starting Scheduler..."		
			q = Queue.Queue()
			for ip in set(self.ip_file):
				if ip != "":
					q.put(ip)

			for i in range(0,int(self.config["threads"])):
				threading.Thread(target=self.run_process,args=(q,)).start()
							

if __name__=='__main__':
	help = '''
Usage: %s <iplist> <verbose>

Example: 
	%s -f iplist.txt -v
	%s --hostsfile iplist.txt --verbose

'''% tuple(os.path.basename(sys.argv[0]) for x in range(3))

	try:
		opts, args = getopt.getopt(sys.argv[1:],"vhf:",["verbose"])

		if len(opts) > 0:
			for opt, value in opts:
				if opt in ("-f","--hostsfile"):
					filename = value
				elif opt in ("-v","--verbose"):
					verbose = True
		else:
			print help		
			sys.exit(2)

	except getopt.GetoptError as ex:
		print str(ex)
		print help
		sys.exit(2)

	scheduler = Scheduler(filename,verbose_option=verbose)
	signal(SIGINT,scheduler.sig_handler)
	scheduler.start_scheduler()