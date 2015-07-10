
dnslist = ["seed.bitcoin.sipa.be",
           "dnsseed.bluematt.me",
           "bitseed.xf2.org",
           "dnsseed.bitcoin.dashjr.org",
           "seed.bitcoinstats.com",
           "seed.bitcoin.jonasschnelli.ch"]

import socket, select, errno, time, random, struct, hashlib
from btchelpers import *

class Peer:
	# 0: connecting, 1: working 100: error!
	def __init__(self, btcmgr, ip, port = 8333, csock = None):
		self.btcmgr = btcmgr
		self._ip = ip
		self._port = port
		self._tosend = ""
		self._inbuffer = ""

		if not csock:
			self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self._fsm = 0
		else:
			self._sock = csock
			self._tosend = verpacket(self._ip, self._port, self._sock.getsockname()[0], self._sock.getsockname()[1])
			self._fsm = 1
			
		self._sock.setblocking(0)

	def readsome(self):
		try:
			data = self._sock.recv(4096)
			if not data:
				# Closed
				self._fsm = 100
				self._last_err = time.time()
			else:
				self._inbuffer += data
		except socket.error, err:
			if err.args[0] != errno.EAGAIN and err.args[0] != errno.EWOULDBLOCK:
				self._fsm = 100
				self._last_err = time.time()

	def writesome(self):
		try:
			w = self._sock.send(self._tosend)
			self._tosend = self._tosend[w:]
		except socket.error, e:
			if err != errno.EAGAIN and err != errno.EWOULDBLOCK:
				self._fsm = 100
				self._last_err = time.time()

	def work(self):
		if self._fsm == 0:
			err = self._sock.connect_ex((self._ip, self._port))
			if err == 0:
				self._fsm = 1
				self._tosend = verpacket(self._ip, self._port, self._sock.getsockname()[0], self._sock.getsockname()[1])
			elif err != errno.EAGAIN and err != errno.EINPROGRESS and err != errno.EWOULDBLOCK:
				self._fsm = 100
				self._last_err = time.time()

		# Read some data
		if self._fsm > 0 and self._fsm < 100:
			self.readsome()
			if self._tosend != "":
				self.writesome()

		if self._fsm == 1:
			# Try to parse received data
			self.parse()

	def parse(self):
		while len(self._inbuffer) >= 24:
			msghdr = self._inbuffer[:24]
			magic = msghdr[:4]
			cmd = msghdr[4:16].strip("\x00")
			plen = struct.unpack("<L", msghdr[16:20])[0]
			pcksm = msghdr[20:24]

			if len(self._inbuffer) - 24 < plen:
				return # Not enough data

			payload = self._inbuffer[24:24+plen]
			if magic == BTCMAGIC and btccs(payload) == pcksm:
				print "Got cmd",cmd
				if cmd == "verack":
					pass # Nothing to do!
				elif cmd == "version":
					self._tosend += genVerAck()
				elif cmd == "inv":
					r = self.btcmgr.parseInv(payload)
					self._tosend += r
				elif cmd == "addr":
					pass
				elif cmd == "ping":
					self._tosend += genPong(payload)
			else:
				print "Dropped malformed packet!", btccs(payload), pcksm

			self._inbuffer = self._inbuffer[24+plen:]

	def getrsock(self):
		if self._fsm < 100:
			return self._sock
		return None

	def getwsock(self):
		if len(self._tosend) > 0 and self._fsm < 100:
			return self._sock
		return None

	def getesock(self):
		if self._fsm < 100:
			return self._sock
		return None

# Bootstrap, get initial list of IPs

btcmgr = BTCMgr()

peers = []
for dns in dnslist:
	peers += [ x[4][0] for x in socket.getaddrinfo(dns, 8333) ]

peers = list(set(peers))
peers = [ Peer(btcmgr, x) for x in peers if "." in x ]

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('', 8333))
server_socket.listen(1)
server_socket.setblocking(0)

while True:
	# Incoming connections
	try:
		client_socket, address = server_socket.accept()
		peers.append(Peer(btcmgr, address[0], address[1], client_socket))
	except socket.error, e:
		pass

	#print "Goto work"
	for p in peers:
		p.work()

	rsockets = [ x.getrsock() for x in peers if x.getrsock() is not None ] + [server_socket]
	wsockets = [ x.getwsock() for x in peers if x.getwsock() is not None ] + [server_socket]
	esockets = [ x.getesock() for x in peers if x.getesock() is not None ] + [server_socket]

	#print "goto sleep", len(rsockets), len(wsockets)

	select.select(rsockets, wsockets, esockets, 1)


