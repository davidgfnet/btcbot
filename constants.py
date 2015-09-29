
bootstrap_dns = ["seed.bitcoin.sipa.be",
                 "dnsseed.bluematt.me",
                 "bitseed.xf2.org",
                 "dnsseed.bitcoin.dashjr.org",
                 "seed.bitcoin.jonasschnelli.ch"]

bootstrap_testnet = ["testnet-seed.bitcoin.petertodd.org"]

def bootstrapDNS(testnet):
	if testnet:
		return bootstrap_testnet
	return bootstrap_dns

def btcPort(testnet):
	return 18333 if testnet else 8333

def btcMagic(testnet):
	if testnet:
		return b'\x0b\x11\x09\x07'
	return b'\xf9\xbe\xb4\xd9'

