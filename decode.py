#!/usr/bin/env python3
import codecs
import sys

import pcapy

def decode(data):
	cmd = (data[0] << 8) | data[1]
	data = data[2:]

	if cmd == 0x0020:
		name = "ping"
	elif cmd == 0x0066:
		name = "status"
	else:
		name = None

	ret = {"cmd": cmd, "name": name, "data": codecs.encode(data, "hex")}

	if name == "status":
		tlv = data[40:]
		ret["tlv"] = {}
		while tlv:
			tag = tlv[0]
			length = max(2, tlv[1]) - 1
			value = 0
			for i in tlv[2:2 + length]:
				value = (value << 8) | i
			ret["tlv"][tag] = value
			tlv = tlv[2 + length:]

	return ret

def dump(filename):
	with pcapy.open_offline(filename) as f:
		while packet := f.next():
			hdr, data = packet
			if hdr is None:
				return

			ethertype = (data[12] << 8) | data[13]
			if ethertype != 0x0800:
				continue
			data = data[14:]

			ipsrc = data[12:16]
			ipproto = data[9]
			if ipproto != 17 or ipsrc != b"\x0A\x00\x07\x02":
				continue
			data = data[20:]

			udpdst = (data[2] << 8) | data[3]
			udplen = (data[4] << 8) | data[5]
			if udpdst != 443:
				continue
			data = data[8:udplen - 8 + 1]

			data = decode(data)

			#print(hdr.getts(), f"{data['cmd']:04x}", data["name"], data["data"])

			if data["name"] == "status":
				#print(hdr.getts(), data["tlv"])
				ts = hdr.getts()
				print(f"temperature,location=home,sensor=external:salus,traits=metric:gauge celsius={data['tlv'][0x1b]/100},target:celsius={data['tlv'][0x1c]/100} {ts[0]}{ts[1]:06}000")
				print(f"boiler,location=home,sensor=external:salus,traits=metric:gauge,salus:ch=power active={data['tlv'][0x1e]} {ts[0]}{ts[1]:06}000")

for filename in sys.argv[1:]:
	dump(filename)
