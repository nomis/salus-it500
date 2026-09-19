#!/usr/bin/env python3
import argparse
import codecs
import socket
import struct
import sys
import traceback

socket.MCAST_JOIN_SOURCE_GROUP = 46

SRC_PORT = 21313
DST_PORT = 19541
GROUP = "ff02::114"

class Salus:
	def __init__(self, interface, ip):
		self.hostname = socket.getfqdn()
		ifidx = socket.if_nametoindex(interface)

		self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind((GROUP, DST_PORT, 0, ifidx))

		gsr_source = (
					struct.pack("@H", socket.AF_INET6)
					+ struct.pack("!HI", SRC_PORT, 0)
					+ socket.inet_pton(socket.AF_INET6, ip)
					+ struct.pack("@I", ifidx)
				).ljust(128, b"\x00")
		gsr_group = (
					struct.pack("@H", socket.AF_INET6)
					+ struct.pack("!HI", DST_PORT, 0)
					+ socket.inet_pton(socket.AF_INET6, GROUP)
					+ struct.pack("@I", ifidx)
				).ljust(128, b"\x00")
		gsreq = struct.pack("@I", ifidx).ljust(len(struct.pack("@P", 0)), b"\x00") + gsr_group + gsr_source
		self.sock.setsockopt(socket.IPPROTO_IPV6, socket.MCAST_JOIN_SOURCE_GROUP, gsreq)

		self.addr = (socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, ip)), SRC_PORT, 0, ifidx)

		self.influx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		self.influx.connect(("127.0.0.1", 8089))

	def receive(self):
		while True:
			(packet, address) = self.sock.recvfrom(65536)
			if address != self.addr:
				continue

			if len(packet) < 14:
				continue

			(tv_sec, tv_usec, incoming) = struct.unpack("=QI?", packet[0:13])
			ts = tv_sec + tv_usec / 1000000
			try:
				data = self.decode(ts, incoming, packet[13:])
				self.process(ts, incoming, data)
			except Exception:
				print(codecs.encode(packet[13:], "hex"), file=sys.stderr)
				traceback.print_exc()

	def decode(self, ts, incoming, data):
		cmd = (data[0] << 8) | data[1]
		data = data[2:]

		if cmd == 0x0020:
			name = "ping"
		elif cmd == 0x0030:
			name = "pong"
		elif cmd == 0x0066:
			name = "status"
		else:
			name = None

		ret = {"cmd": cmd, "name": name, "data": codecs.encode(data, "hex")}

		if name == "status" and len(data) >= 40:
			tlv = data[40:]
			ret["tlv"] = {}
			while len(tlv) >= 2:
				tag = tlv[0]
				length = max(2, tlv[1]) - 1
				value = 0
				if len(tlv) < 2 + length:
					break
				for i in tlv[2:2 + length]:
					value = (value << 8) | i
				ret["tlv"][tag] = value
				tlv = tlv[2 + length:]

		return ret

	def process(self, ts, incoming, data):
		print(f"{ts:.6f}", "->" if incoming else "<-", f"{data['cmd']:04x}", data["name"], data["data"])

		ts = int(ts * 1000000000)

		if incoming and data["name"] == "status":
			#print(hdr.getts(), data["tlv"])
			self.send(f"temperature,location=home,host={self.hostname},sensor=external:salus,traits=metric:gauge celsius={data['tlv'][0x1b]/100},target:celsius={data['tlv'][0x1c]/100} {ts}".encode("utf-8"))
			self.send(f"boiler,location=home,host={self.hostname},sensor=external:salus,traits=metric:gauge,salus:ch=power active={data['tlv'][0x1e]} {ts}".encode("utf-8"))

	def send(self, message):
		print(message)
		self.influx.send(message)

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("interface")
	parser.add_argument("ip")
	args = parser.parse_args()
	Salus(**vars(args)).receive()
