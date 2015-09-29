
import socket, select, errno, random, struct, hashlib
from btchelpers import *
from constants import *
from time import time
import argparse

parser = argparse.ArgumentParser(description='BTC notify bot')
parser.add_argument('--testnet', dest='testnet', action='store_true',
                    help='Use testnet network')

args = parser.parse_args()

MAX_RETRIES = 10

class Peer:
	maxheight = 0

	def __init__(self, btcmgr, ip, port, csock = None):
		self.btcmgr = btcmgr
		self._ip = ip
		self._port = port
		self._tosend = ""
		self._inbuffer = ""
		self._lasterr = "unset"
		self._error = False
		self._retries = 0
		self._ctime = 0
		self._breceived = 0
		self._bsent = 0
		self._bps = 0
		self._goodness = 0

		if not csock:
			if "." in ip:
				self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			else:
				self._sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
			self._connected = False
		else:
			self._sock = csock
			self._tosend = verpacket(args.testnet, Peer.maxheight, self._ip, self._port, self._sock.getsockname()[0], self._sock.getsockname()[1])
			self._connected = True
			print "Connected to", self._ip
			
		self._sock.setblocking(0)

	def isOK(self):
		return self._connected and not self._error

	def setErr(self, errcode):
		self._error = True
		self._lasterr = errcode
		self._last_err = time()
		self._retries += 1

	def close(self):
		self._breceived = 0
		self._bsent = 0
		self._sock.close()
		self._connected = False
		self._error = True
		self._retries = MAX_RETRIES

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
			except socket.error, err:
				if err.args[0] != errno.EAGAIN and err.args[0] != errno.EWOULDBLOCK:
					self.setErr("Error at write()")
				break

	def work(self):
		if not self._error:
			if not self._connected:
				err = self._sock.connect_ex((self._ip, self._port))
				if err == 0:
					self._ctime = time()
					self._breceived = 0
					self._bsent = 0
					self._connected = True
					self._tosend = verpacket(args.testnet, Peer.maxheight, self._ip, self._port, self._sock.getsockname()[0], self._sock.getsockname()[1])
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
			if magic == btcMagic(args.testnet) and btccs(payload) == pcksm:
				#print "Got cmd",cmd
				if cmd == "verack":
					pass # Nothing to do!
				elif cmd == "version":
					# Parse version to get blockheight
					vdata = parseVersion(payload)
					if "height" in vdata:
						Peer.maxheight = max(Peer.maxheight, vdata["height"])
					self._tosend += genVerAck(args.testnet)
				elif cmd == "inv":
					self.btcmgr.parseInv(payload)
				elif cmd == "addr":
					pass
				elif cmd == "ping":
					self._tosend += genPong(args.testnet, payload)
				elif cmd == "getaddr":
					self._tosend += getAddr(args.testnet, self.btcmgr.peers)
				elif cmd == "tx":
					self.btcmgr.parseTx(payload)
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
server_socket.bind(('', btcPort(args.testnet)))
server_socket.listen(1)
server_socket.setblocking(0)

btcmgr = BTCMgr(args.testnet)

# Bootstrap, get initial list of IPs
iplist = set()
for dns in bootstrapDNS(args.testnet):
	print "Resolving", dns, "..."
	for ip in socket.getaddrinfo(dns, btcPort(args.testnet)):
		iplist.add(ip[4][0])

btcmgr.peers = [ Peer(btcmgr, x, btcPort(args.testnet)) for x in iplist ]

while True:
	# Incoming connections
	try:
		client_socket, address = server_socket.accept()
		btcmgr.peers.append(Peer(btcmgr, address[0], address[1], client_socket))
	except socket.error, e:
		pass

	# Do make the whole BTCmgr work
	btcmgr.work()

	# Make peers work
	for p in btcmgr.peers:
		p.work()
		if p._error and p._retries == MAX_RETRIES:
			print p._lasterr

	# Remove dead peers
	btcmgr.peers = [ p for p in btcmgr.peers if not p._error or p._retries < MAX_RETRIES ]

	rsockets = [ x.getrsock() for x in btcmgr.peers if x.getrsock() is not None ] + [server_socket]
	wsockets = [ x.getwsock() for x in btcmgr.peers if x.getwsock() is not None ] + [server_socket]
	esockets = [ x.getesock() for x in btcmgr.peers if x.getesock() is not None ] + [server_socket]

	#print "Goto sleep", len(rsockets), len(wsockets), len(peers)

	rs,ws,es = select.select(rsockets, wsockets, esockets, 10)



