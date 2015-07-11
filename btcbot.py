
dnslist = ["seed.bitcoin.sipa.be",
           "dnsseed.bluematt.me",
           "bitseed.xf2.org",
           "dnsseed.bitcoin.dashjr.org",
           #"seed.bitcoinstats.com",
           "seed.bitcoin.jonasschnelli.ch"]

import socket, select, errno, time, random, struct, hashlib
from btchelpers import *

MAX_RETRIES = 10

class Peer:
	maxheight = 0

	def __init__(self, btcmgr, ip, port = 8333, csock = None):
		self.btcmgr = btcmgr
		self._ip = ip
		self._port = port
		self._tosend = ""
		self._inbuffer = ""
		self._error = False
		self._retries = 0

		if not csock:
			if "." in ip:
				self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			else:
				self._sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
			self._connected = False
		else:
			self._sock = csock
			self._tosend = verpacket(Peer.maxheight, self._ip, self._port, self._sock.getsockname()[0], self._sock.getsockname()[1])
			self._connected = True
			print "Connected to", self._ip
			
		self._sock.setblocking(0)

	def setErr(self, errcode):
		self._error = True
		self._lasterr = errcode
		self._last_err = time.time()
		self._retries += 1

	def readsome(self):
		while True:
			try:
				data = self._sock.recv(4096)
				if not data:
					# Closed connection!
					self.setErr("Connection closed by peer")
					break
				else:
					self._inbuffer += data
			except socket.error, err:
				if err.args[0] != errno.EAGAIN and err.args[0] != errno.EWOULDBLOCK:
					self.setErr("Error at read()")
				break

	def writesome(self):
		while len(self._tosend) > 0:
			try:
				w = self._sock.send(self._tosend)
				self._tosend = self._tosend[w:]
			except socket.error, e:
				if err != errno.EAGAIN and err != errno.EWOULDBLOCK:
					self.setErr("Error at write()")
				break

	def work(self):
		if not self._error:
			if not self._connected:
				err = self._sock.connect_ex((self._ip, self._port))
				if err == 0:
					self._connected = True
					self._tosend = verpacket(Peer.maxheight, self._ip, self._port, self._sock.getsockname()[0], self._sock.getsockname()[1])
				elif err != errno.EAGAIN and err != errno.EINPROGRESS and err != errno.EWOULDBLOCK and err != errno.EALREADY:
					self.setErr("Error at connecting to %s: %d"%(self._ip, err))

			if self._connected:
				# Read some data
				self.readsome()
				# Write some data
				if self._tosend != "":
					self.writesome()

				# Try to parse received data
				self.parse()
		else:
			if self._retries < MAX_RETRIES:
				self._connected = False
				self._error = False
				self._tosend = ""
				self._inbuffer = ""

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
				#print "Got cmd",cmd
				if cmd == "verack":
					pass # Nothing to do!
				elif cmd == "version":
					# Parse version to get blockheight
					vdata = parseVersion(payload)
					if "height" in vdata:
						Peer.maxheight = max(Peer.maxheight, vdata["height"])
					self._tosend += genVerAck()
				elif cmd == "inv":
					r = self.btcmgr.parseInv(payload)
					self._tosend += r
				elif cmd == "addr":
					pass
				elif cmd == "ping":
					self._tosend += genPong(payload)
				elif cmd == "getaddr":
					self._tosend += getAddr(self.btcmgr.peers)
			else:
				print "Dropped malformed packet!", btccs(payload), pcksm

			self._inbuffer = self._inbuffer[24+plen:]

	def getrsock(self):
		if not self._error:
			return self._sock
		return None

	def getwsock(self):
		if not self._error and len(self._tosend) > 0:
			return self._sock
		return None

	def getesock(self):
		if not self._error:
			return self._sock
		return None

# Set up socket server for incoming connections
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('', 8333))
server_socket.listen(1)
server_socket.setblocking(0)

btcmgr = BTCMgr()

# Bootstrap, get initial list of IPs
iplist = set()
for dns in dnslist:
	print "Resolving", dns, "..."
	for ip in socket.getaddrinfo(dns, 8333):
		iplist.add(ip[4][0])

btcmgr.peers = [ Peer(btcmgr, x) for x in iplist ]

while True:
	# Incoming connections
	try:
		client_socket, address = server_socket.accept()
		btcmgr.peers.append(Peer(btcmgr, address[0], address[1], client_socket))
	except socket.error, e:
		pass

	# Make peers work
	for p in btcmgr.peers:
		p.work()
		if p._error and p._retries == MAX_RETRIES:
			print p._lasterr

	btcmgr.peers = [ p for p in btcmgr.peers if not p._error or p._retries < MAX_RETRIES ]

	rsockets = [ x.getrsock() for x in btcmgr.peers if x.getrsock() is not None ] + [server_socket]
	wsockets = [ x.getwsock() for x in btcmgr.peers if x.getwsock() is not None ] + [server_socket]
	esockets = [ x.getesock() for x in btcmgr.peers if x.getesock() is not None ] + [server_socket]

	#print "Goto sleep", len(rsockets), len(wsockets), len(peers)

	rs,ws,es = select.select(rsockets, wsockets, esockets, 10)



