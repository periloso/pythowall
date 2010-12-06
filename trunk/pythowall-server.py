#!/usr/bin/python
import time, os, sys
import urlparse, SocketServer, urllib, BaseHTTPServer

class PythoWall (BaseHTTPServer.BaseHTTPRequestHandler):
	global modemThread
	__base = BaseHTTPServer.BaseHTTPRequestHandler
	__base_handle = __base.handle
	server_version = 'PythoWall Server/1.0'
	attackers = []

	def getToDict(self, qs):
		dict = {}
		try:
			for singleValue in qs.split('&'):
				keyVal = singleValue.split('=')
				dict[urllib.unquote_plus(keyVal[0])] = urllib.unquote_plus(keyVal[1])
		except IndexError:
			return 0
		return dict
	def getStatus(self):
		for element in self.attackers:
			if element[1] <= int(time.time()):
				self.attackers.remove([element[0], element[1]])
		retVal = ''
		for element in self.attackers:
			retVal += element[0] + '\n'
		return retVal.strip('\n')
	def log_message(self, format, *args):
		pass
	def do_GET(self):
		(scm, netloc, path, params, query, fragment) = urlparse.urlparse(self.path, 'http')
		if scm != 'http':
			self.send_error(501, "The server does not support the facility required.")
			return
		elif ((path != '/addFilter') or (path != '/getStatus')) and (self.command != 'GET'):
			self.send_error(403, "The server understood the request, but is refusing to fulfill it. Authorization will not help and the request MUST NOT be repeated")
			return
		elif (path == '/addFilter') and (self.command == 'GET'):
			getData = self.getToDict(query)
			try:
				if getData == 0:
					raise KeyError
				if (getData['attacker'] != None) == (getData['jailtime'] != None):
					pass
				attackFound = False
				for element in self.attackers:
					if element[0] == getData['attacker']:
						attackFound = True
				if attackFound == False:
					self.attackers.append([getData['attacker'], time.time() + (60*int(getData['jailtime']))])
				self.send_response(200)
				self.send_header('Content-type', 'text/plain')
				self.end_headers()
				self.wfile.write(self.getStatus())
			except KeyError:
				self.send_error(403, "The server understood the request, but is refusing to fulfill it. Authorization will not help and the request MUST NOT be repeated")
			return
		elif (path == '/getStatus') and (self.command == 'GET'):
			self.send_response(200)
			self.send_header('Content-type', 'text/plain')
			self.end_headers()
			self.wfile.write(self.getStatus())
	do_HEAD		= do_GET
	do_POST		= do_GET
	do_PUT		= do_GET
	do_DELETE	= do_GET
	do_CONNECT	= do_GET

class ThreadingHTTPServer (SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer): pass

fpid = os.fork() # Daemonize
if fpid !=0:
	sys.exit(0)

pythoWall = ThreadingHTTPServer(("0.0.0.0", 4010), PythoWall)
try:
	pythoWall.serve_forever()
except KeyboardInterrupt:
	print ""
	pythoWall.server_close()
