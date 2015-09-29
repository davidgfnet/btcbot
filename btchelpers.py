
import socket, random, struct, hashlib
from constants import *
from time import time

def hexrev(s): return "".join(reversed([s[i:i+2] for i in range(0, len(s), 2)]))

def ip6_to_integer(ip6):
	ip6 = socket.inet_pton(socket.AF_INET6, ip6)
	a, b = struct.unpack(">QQ", ip6)
	return (a << 64) | b

def ip4_to_integer(ip):
	return struct.unpack("!I", socket.inet_aton(ip))[0]

def iptoint(ip):
	if ":" not in ip:
		return ip4_to_integer(ip)
	else:
		return ip6_to_integer(ip)

def varint(num):
	if num == 0:
		return b'\x00'
	elif (num < 0xfd):
		return chr(num)
	elif (num <= 0xffff):
		return b'\xfd' + struct.pack('<H', num)
	elif (num <= 0xffffffff):
		return b'\xfe' + struct.pack('<L', num)
	else:
		return b'\xff' + struct.pack('<Q', num)

def parsevarint(payload):
	if (len(payload) == 0): return -1, payload

	f = ord(payload[0])
	if f < 0xfd:
		return (f, payload[1:])
	elif f == 0xfd:
		if (len(payload) < 3): return -1, payload
		return (struct.unpack('>H', payload[1:3])[0], payload[3:])
	elif f == 0xfe:
		if (len(payload) < 5): return -1, payload
		return (struct.unpack('>L', payload[1:5])[0], payload[5:])
	else:
		if (len(payload) < 9): return -1, payload
		return (struct.unpack('>Q', payload[1:9])[0], payload[9:])

def varstr(st):
	ret = varint(len(st))
	return ret + st.encode("utf-8")

def btccs(payload):
	return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

def dsha256(payload):
	return hashlib.sha256(hashlib.sha256(payload).digest()).digest()

def netaddr(ip, port):
	ret = struct.pack('<Q', 1)
	ipv4 = ":" not in ip
	ip = iptoint(ip)

	if ipv4:
		ret += struct.pack('<Q', 0)  # 16 byte IP
		ret += struct.pack('>L', 0xFFFF)
		ret += struct.pack('>L', ip)
	else:
		ret += struct.pack('<QQ', ip/(2**64), ip%(2**64))

	ret += struct.pack('>H', port)
	return ret

def pktwrap(testnet, cmd, payload):
	ret  = btcMagic(testnet)  # Magic
	ret += cmd  # Command
	ret += struct.pack('<L', len(payload))  # Payload length
	ret += btccs(payload)
	ret += payload
	return ret

def gencmd(st):
	return st + b'\x00' * (12-len(st))

def getAddr(testnet, peers):
	ret = ""
	ts = int(time())
	n = 0
	for p in peers:
		if p._connected and not p._error:
			n += 1
			ret += struct.pack('<L', ts)
			ret += netaddr(p._ip, p._port)

	return pktwrap(testnet, gencmd("addr"), varint(n) + ret)

def verpacket(testnet, height, ip, port, localip, localport):
	payload = struct.pack('<L', 70002)  # Proto version
	payload += struct.pack('<Q', 1)    # Bitfield features
	payload += struct.pack('<Q', int(time()))    # timestamp
	payload += netaddr(ip, port)
	payload += netaddr(localip, localport)
	payload += struct.pack('<Q', int(random.random()*(2**64)))    # nonce
	#payload += varstr('/btcbot:0.1/')
	payload += varstr('/Satoshi:0.9.1/')
	payload += struct.pack('<L', height)  # Fake the height
	payload += b'\x01'   # Do we relay?

	return pktwrap(testnet, gencmd("version"), payload)

def parseVersion(payload):
	ret = {}
	if len(payload) < 85: return ret

	ret["version"] = struct.unpack("<L", payload[:4])[0]
	ret["services"] = struct.unpack("<Q", payload[4:12])[0]
	ret["timestamp"] = struct.unpack("<Q", payload[12:20])[0]
	ret["nonce"] = struct.unpack("<Q", payload[72:80])[0]
	useragentsize, payload = parsevarint(payload[80:])
	if len(payload) < useragentsize + 4: return ret
	payload = payload[useragentsize:]
	ret["height"] = struct.unpack("<L", payload[:4])[0]
	return ret

def genPong(testnet, payload):
	return pktwrap(testnet, gencmd("pong"), payload)

def genVerAck(testnet):
	return pktwrap(testnet, gencmd("verack"), "")

class BTCOBJ:
	def __init__(self):
		self._received = time()
		self._data = None
		self._req = False
	

class BTCTX(BTCOBJ):
	def __init__(self):
		BTCOBJ.__init__(self)
		self._type = 1

class BTCBLOCK(BTCOBJ):
	def __init__(self):
		BTCOBJ.__init__(self)
		self._type = 2

class BTCMgr:
	MAX_CONNECTED_PEERS = 30

	TXTO = 60*5  # Keep TX in the list for 5 minutes
	TXBCST = 4   # Number of nodes that will get relayed data
	TXREQN = 3   # Number of nodes to ask for TX

	MAX_BLOCKS = 8  # Since each block is ~1MB, keep resources down
	BLBCST = 0
	BLREQN = 2

	def __init__(self, testnet):
		self._txlist = {}
		self._bllist = {}
		self._tick = 0
		self._slowtick = 0
		self.peers = []
		self.testnet = testnet

	def genGetData(self, di):
		ret = ""
		for h, inv in di.items():
			inv._req = True
			ret += struct.pack('<L', inv._type)
			ret += h

		ret = varint(len(di)) + ret
		return pktwrap(self.testnet, gencmd("getdata"), ret)

	def cleanUp(self):
		# Clean old TX
		self._txlist = { k:v for k,v in self._txlist.items()
								if v._received + BTCMgr.TXTO > time() }

	def parseInv(self, payload):
		# Parse and look for TX
		num, payload = parsevarint(payload)
		if num*36 != len(payload): return

		for i in range(num):
			inv = payload[i*36: i*36+36]
			invtype = struct.unpack('<L', inv[:4])[0]
			invhash = inv[4:]

			if invtype == 1:
				if invhash not in self._txlist.keys():
					self._txlist[invhash] = BTCTX()
					#print "TX", hexrev(invhash.encode("hex"))
			elif invtype == 2:
				if invhash not in self._bllist.keys():
					self._bllist[invhash] = BTCBLOCK()
					print "BLOCK", hexrev(invhash.encode("hex"))

	def parseTx(self, payload):
		txh = dsha256(payload)
		if txh in self._txlist:
			self._txlist[txh]._data = payload
		#print "Got TX response", hexrev(txh.encode("hex"))

	def work(self):
		# Look for empty TX/BL and request them
		if self._tick + 1 < time():
			self._tick = time()

			print "Number of TX:", len(self._txlist)
			print "Number of BL:", len(self._bllist)
			print "Number of peers:", len(self.peers)

			# Get connected peers
			cpeers = [ x for x in self.peers if x.isOK() ]
			random.shuffle(cpeers)

			txobjs = { k:v for k,v in self._txlist.items() if not v._data and not v._req }
			# Pick TXREQN random peers
			for p in cpeers[:BTCMgr.TXREQN]:
				p._tosend += self.genGetData(txobjs)

			blobjs = { k:v for k,v in self._bllist.items() if not v._data and not v._req }
			for p in cpeers[:BTCMgr.BLREQN]:
				p._tosend += self.genGetData(blobjs)

			self.cleanUp()

		if self._slowtick + 10 < time():
			self._slowtick = time()

			# Remove the excess peers
			if len(self.peers) > BTCMgr.MAX_CONNECTED_PEERS:
				# Recompute peer goodness
				t = time()
				bws = [ (p._breceived + p._bsent) / (t - p._ctime) for p in self.peers ]
				mbw = max(bws)+0.1
				for i, p in enumerate(self.peers):
					p._goodness = bws[i] / mbw
					
				candidates = sorted(self.peers, key=lambda x: x._goodness, reverse=True)
				candidates = candidates[BTCMgr.MAX_CONNECTED_PEERS:]

				# Disconnect these guys, allow 2 minutes of "node testing"
				for p in candidates:
					if p._connected and p._ctime + 30 < t:
						p.close()


