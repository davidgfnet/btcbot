
import socket, time, random, struct, hashlib

BTCMAGIC = b'\xf9\xbe\xb4\xd9'

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

def pktwrap(cmd, payload):
	ret  = BTCMAGIC  # Magic
	ret += cmd  # Command
	ret += struct.pack('<L', len(payload))  # Payload length
	ret += btccs(payload)
	ret += payload
	return ret

def gencmd(st):
	return st + b'\x00' * (12-len(st))

def getAddr(peers):
	ret = ""
	ts = int(time.time())
	n = 0
	for p in peers:
		if p._connected and not p._error:
			n += 1
			ret += struct.pack('<L', ts)
			ret += netaddr(p._ip, p._port)

	return pktwrap(gencmd("addr"), varint(n) + ret)

def verpacket(height, ip, port, localip, localport):
	payload = struct.pack('<L', 70002)  # Proto version
	payload += struct.pack('<Q', 1)    # Bitfield features
	payload += struct.pack('<Q', int(time.time()))    # timestamp
	payload += netaddr(ip, port)
	payload += netaddr(localip, localport)
	payload += struct.pack('<Q', int(random.random()*(2**64)))    # nonce
	#payload += varstr('/btcbot:0.1/')
	payload += varstr('/Satoshi:0.9.1/')
	payload += struct.pack('<L', height)  # Fake the height
	payload += b'\x01'   # Do we relay?

	return pktwrap(gencmd("version"), payload)

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

def genPong(payload):
	return pktwrap(gencmd("pong"), payload)

def genVerAck():
	return pktwrap(gencmd("verack"), "")

class BTCTX:
	def __init__(self, h):
		self._h = h
		self._requested = 0

class BTCMgr:
	def __init__(self):
		self._txlist = []
		self.peers = []

	def genGetData(self):
		ret = ""
		for inv in self._txlist:
			ret += struct.pack('<L', 1)
			ret += inv._h

		ret = varint(len(self._txlist)) + ret
		self._txlist = []
		return pktwrap(gencmd("getdata"), ret)

	def parseInv(self, payload):
		# Parse and look for TX
		num, payload = parsevarint(payload)
		if num*36 != len(payload): return ""

		for i in range(num):
			inv = payload[i*36: i*36+36]
			invtype = struct.unpack('<L', inv[:4])[0]
			invhash = inv[4:]

			if invtype == 1:
				if invhash not in [ x._h for x in self._txlist ]:
					self._txlist.append(BTCTX(invhash))
					print "TX", invhash.encode("hex")
			elif invtype == 2:
				print "BLOCK", invhash.encode("hex")

		if len(self._txlist) > 32:
			return self.genGetData()
		return ""





