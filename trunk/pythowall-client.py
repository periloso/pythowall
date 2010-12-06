#!/usr/bin/python
import time, os, sys, re, urllib
from threading import Thread
from threading import Timer

serverIP = '192.168.255.254'
paths = []

# SSH
paths.append({'path': '/var/log/auth.log',
			  'regex': 'sshd.*?Failed password for .*? from ([0-9\.]*) port [0-9]*',
			  'maxRetries': 3,
			  'jailtime': 6*60}) # 6 hours
"""
# Asterisk
paths.append({'path': '/var/log/asterisk/messages',
			  'regex': "' failed for '(.*?)'",
			  'maxRetries': 5,
			  'jailtime': 6*60})
# Dovecot
paths.append({'path': '/var/log/auth.log',
			  'regex': '.*dovecot-auth.*authentication failure.*rhost=([0-9\.]*).*',
			  'maxRetries': 5,
			  'jailtime': 6*60})
"""

def updateList(filterList = ''):
	global iptables, clients, iptablesList, serverIP
	toBeRemoved = []
	for element in clients: # Purge clients not active anymore
		if clients[element]['retries'] >= clients[element]['maxRetries']:
			query = 'attacker=' + element + '&jailtime=' + str(clients[element]['jailtime'])
			try:
				filterList = urllib.urlopen('http://' + serverIP + ':4010/addFilter?'+query).read().split('\n')
				updateList(filterList)
				toBeRemoved.append(element)
			except IOError:
				pass
		if (clients[element]['time'] + 3600) < time.time():
			toBeRemoved.append(element)
	for element in toBeRemoved:
		del(clients[element])
	if (filterList != '') and (filterList != None):
		iptablesLines = os.popen(iptables + ' -L pythowall -n --line-numbers').read().strip('\n').split('\n')[2:]
		iptablesList = []
		iptablesLines.reverse()
		for element in iptablesLines: # First delete expired IPs
			if len(element) != 0:
				ruleID = element.split()[0]
				attackerIP = element.split()[4]
				try:
					if filterList.index(attackerIP) != None:
						iptablesList.append(attackerIP)
				except ValueError:
					os.system(iptables + ' -D pythowall ' + ruleID)
		for element in filterList:
			if len(element) != 0: # Then add new IPs
				try:
					if iptablesList.index(element):
						pass
				except ValueError:
					os.system(iptables + ' -I pythowall -s ' + element + ' -j DROP')
					iptablesList.append(element)
	else:
		while (isRunning):
			try:
				filterList = urllib.urlopen('http://' + serverIP + ':4010/getStatus').read().split('\n')
				updateList(filterList)
			except IOError:
				pass
			time.sleep(20)

def loggerThread(filename, regex, jailtime=30, maxRetries=5):
	global serverIP, isRunning, clients
	if not os.path.exists(filename):
		return 0
	file = open(filename,'r')

	filesize = os.path.getsize(filename)
	file.seek(filesize)

	while isRunning:
		if file.tell() < filesize: # Logfile has been truncated
			filesize = 0
			file.seek(0)
		else:
			filesize = file.tell()
		line = file.readline()
		if not line:
			time.sleep(1)
			file.seek(filesize)
		else:
			m = re.search(regex, line)
			if m != None: # Match found!
				attacker = m.group(1)
				if clients.has_key(attacker):
					element = clients[attacker]
					if (element['retries']+1 >= maxRetries) and (time.time() <= (element['time']+3600)):
						query = 'attacker=' + attacker + '&jailtime=' + str(jailtime)
						try:
							filterList = urllib.urlopen('http://' + serverIP + ':4010/addFilter?'+query).read().split('\n')
							updateList(filterList)
							del(clients[attacker])
						except IOError:
							pass
					else:
						element['retries'] += 1
						element['time'] = time.time()
						element['maxRetries'] = maxRetries
						element['jailtime'] = jailtime
						clients[attacker] = element
				else:
					try:
						if iptablesList.index(attacker):
							pass
					except ValueError:
						clients[attacker] = {'retries': 1, 'time': time.time()}

fpid = os.fork() # Daemonize
if fpid !=0:
	sys.exit(0)

iptablesList = []
clients = {}
isRunning = 1
iptables = os.popen("whereis iptables").read().split(' ')[1] # Let's find iptables

for element in paths:
	if not element.has_key('maxRetries'):
		element['maxRetries'] = 5
	if not element.has_key('jailtime'):
		element['jailtime'] = 6*60
	logger = Thread(target=loggerThread, args=(element['path'], element['regex'], element['jailtime'], element['maxRetries'])).start()
	updater = Thread(target=updateList()).start()
	try:
		while isRunning:
			pass
	except KeyboardInterrupt:
		print ""
		isRunning = 0
	