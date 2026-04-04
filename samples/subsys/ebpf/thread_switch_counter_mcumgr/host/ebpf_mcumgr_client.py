#!/usr/bin/env python3
"""Minimal MCUmgr client for the Zephyr eBPF management group over UART."""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path
from typing import Any

try:
	import serial
except ModuleNotFoundError as exc:  # pragma: no cover - import guard
	raise SystemExit(
		"pyserial is required. Install it with: python -m pip install pyserial"
	) from exc


MGMT_OP_READ = 0
MGMT_OP_READ_RSP = 1
MGMT_OP_WRITE = 2
MGMT_OP_WRITE_RSP = 3

SMP_VERSION_2 = 1

ZEPHYR_MGMT_GRP_EBPF = 62

ZEPHYR_MGMT_GRP_EBPF_CMD_LOAD = 0
ZEPHYR_MGMT_GRP_EBPF_CMD_ENABLE = 1
ZEPHYR_MGMT_GRP_EBPF_CMD_DISABLE = 2
ZEPHYR_MGMT_GRP_EBPF_CMD_UNLOAD = 3
ZEPHYR_MGMT_GRP_EBPF_CMD_DUMP = 4
ZEPHYR_MGMT_GRP_EBPF_CMD_MAP_READ = 5

SERIAL_HDR_PKT = b"\x06\x09"
SERIAL_HDR_FRAG = b"\x04\x14"
SERIAL_MAX_FRAME = 127
SERIAL_MAX_DECODED_CHUNK = ((SERIAL_MAX_FRAME - 3) // 4) * 3

_CBOR_BREAK = object()


class McumgrError(RuntimeError):
	"""Raised when the target returns an MCUmgr group error."""


class CborDecodeError(ValueError):
	"""Raised when a CBOR payload cannot be decoded by the minimal decoder."""


def crc16_itu_t(data: bytes) -> int:
	crc = 0
	for byte in data:
		crc ^= byte << 8
		for _ in range(8):
			if crc & 0x8000:
				crc = ((crc << 1) ^ 0x1021) & 0xFFFF
			else:
				crc = (crc << 1) & 0xFFFF
	return crc


def encode_cbor(value: Any) -> bytes:
	if isinstance(value, bool):
		return b"\xf5" if value else b"\xf4"
	if value is None:
		return b"\xf6"
	if isinstance(value, int):
		major = 0 if value >= 0 else 1
		encoded = value if value >= 0 else -1 - value
		return _encode_cbor_head(major, encoded)
	if isinstance(value, bytes):
		return _encode_cbor_head(2, len(value)) + value
	if isinstance(value, str):
		encoded = value.encode("utf-8")
		return _encode_cbor_head(3, len(encoded)) + encoded
	if isinstance(value, (list, tuple)):
		encoded_items = b"".join(encode_cbor(item) for item in value)
		return _encode_cbor_head(4, len(value)) + encoded_items
	if isinstance(value, dict):
		encoded_items = b"".join(encode_cbor(key) + encode_cbor(item) for key, item in value.items())
		return _encode_cbor_head(5, len(value)) + encoded_items
	raise TypeError(f"Unsupported CBOR type: {type(value)!r}")


def _encode_cbor_head(major: int, value: int) -> bytes:
	if value < 24:
		return bytes([(major << 5) | value])
	if value < 0x100:
		return bytes([(major << 5) | 24, value])
	if value < 0x10000:
		return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
	if value < 0x100000000:
		return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
	return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def decode_cbor(data: bytes) -> Any:
	value, offset = _decode_cbor_item(data, 0)
	if value is _CBOR_BREAK:
		raise CborDecodeError("Unexpected CBOR break marker at top level")
	if offset != len(data):
		raise CborDecodeError("Trailing bytes after CBOR payload")
	return value


def _decode_cbor_item(data: bytes, offset: int) -> tuple[Any, int]:
	if offset >= len(data):
		raise CborDecodeError("Unexpected end of CBOR data")

	initial = data[offset]
	major = initial >> 5
	additional = initial & 0x1F
	offset += 1

	if major == 7 and additional == 31:
		return _CBOR_BREAK, offset

	if major in (0, 1, 2, 3, 4, 5):
		if additional == 31:
			if major == 4:
				items = []
				while True:
					item, offset = _decode_cbor_item(data, offset)
					if item is _CBOR_BREAK:
						return items, offset
					items.append(item)
			if major == 5:
				items = {}
				while True:
					key, offset = _decode_cbor_item(data, offset)
					if key is _CBOR_BREAK:
						return items, offset
					item, offset = _decode_cbor_item(data, offset)
					if item is _CBOR_BREAK:
						raise CborDecodeError("Unexpected CBOR break marker in map value")
					items[key] = item
			if major == 2 or major == 3:
				chunks: list[bytes] = []
				while True:
					item, offset = _decode_cbor_item(data, offset)
					if item is _CBOR_BREAK:
						joined = b"".join(chunks)
						return joined if major == 2 else joined.decode("utf-8"), offset
					if not isinstance(item, (bytes, bytearray)):
						raise CborDecodeError("Invalid chunk type inside indefinite-length string")
					chunks.append(bytes(item))
			raise CborDecodeError(f"Unsupported indefinite-length CBOR major type {major}")

		length, offset = _decode_cbor_length(data, offset, additional)

		if major == 0:
			return length, offset
		if major == 1:
			return -1 - length, offset
		if major == 2:
			end = offset + length
			if end > len(data):
				raise CborDecodeError("Truncated CBOR byte string")
			return data[offset:end], end
		if major == 3:
			end = offset + length
			if end > len(data):
				raise CborDecodeError("Truncated CBOR text string")
			return data[offset:end].decode("utf-8"), end
		if major == 4:
			items = []
			for _ in range(length):
				item, offset = _decode_cbor_item(data, offset)
				items.append(item)
			return items, offset
		items = {}
		for _ in range(length):
			key, offset = _decode_cbor_item(data, offset)
			item, offset = _decode_cbor_item(data, offset)
			items[key] = item
		return items, offset

	if major == 7:
		if additional == 20:
			return False, offset
		if additional == 21:
			return True, offset
		if additional == 22:
			return None, offset

	raise CborDecodeError(f"Unsupported CBOR major type {major} additional {additional}")


def _decode_cbor_length(data: bytes, offset: int, additional: int) -> tuple[int, int]:
	if additional < 24:
		return additional, offset
	if additional == 24:
		return _read_uint(data, offset, 1)
	if additional == 25:
		return _read_uint(data, offset, 2)
	if additional == 26:
		return _read_uint(data, offset, 4)
	if additional == 27:
		return _read_uint(data, offset, 8)
	raise CborDecodeError(f"Unsupported CBOR additional info {additional}")


def _read_uint(data: bytes, offset: int, width: int) -> tuple[int, int]:
	end = offset + width
	if end > len(data):
		raise CborDecodeError("Truncated CBOR integer")
	return int.from_bytes(data[offset:end], "big"), end


def build_smp_packet(op: int, command_id: int, seq: int, payload: dict[str, Any]) -> bytes:
	payload_bytes = encode_cbor(payload)
	first = (op & 0x07) | ((SMP_VERSION_2 & 0x03) << 3)
	header = bytes([first, 0])
	header += len(payload_bytes).to_bytes(2, "big")
	header += ZEPHYR_MGMT_GRP_EBPF.to_bytes(2, "big")
	header += bytes([seq & 0xFF, command_id & 0xFF])
	return header + payload_bytes


def parse_smp_packet(packet: bytes) -> tuple[dict[str, int], dict[str, Any]]:
	if len(packet) < 8:
		raise ValueError("SMP packet too short")

	first = packet[0]
	payload_len = int.from_bytes(packet[2:4], "big")
	group = int.from_bytes(packet[4:6], "big")
	seq = packet[6]
	command_id = packet[7]
	payload = packet[8:]
	if len(payload) != payload_len:
		raise ValueError("SMP payload length mismatch")

	header = {
		"op": first & 0x07,
		"version": (first >> 3) & 0x03,
		"flags": packet[1],
		"group": group,
		"seq": seq,
		"command_id": command_id,
	}

	decoded = decode_cbor(payload)
	if not isinstance(decoded, dict):
		raise ValueError("Expected a CBOR map payload")

	return header, decoded


def normalize_for_json(value: Any) -> Any:
	if isinstance(value, bytes):
		return {"len": len(value), "hex": value.hex()}
	if isinstance(value, list):
		return [normalize_for_json(item) for item in value]
	if isinstance(value, dict):
		return {str(key): normalize_for_json(item) for key, item in value.items()}
	return value


class SerialSmpTransport:
	def __init__(self, port: str, baud: int, line_timeout: float):
		self._serial = serial.Serial(port=port, baudrate=baud, timeout=line_timeout, write_timeout=line_timeout)
		self._rx_payload = bytearray()
		self._rx_expected_len: int | None = None

	def close(self) -> None:
		self._serial.close()

	def __enter__(self) -> "SerialSmpTransport":
		return self

	def __exit__(self, exc_type, exc, tb) -> None:
		self.close()

	def send_packet(self, packet: bytes) -> None:
		crc = crc16_itu_t(packet)
		encoded_source = len(packet + crc.to_bytes(2, "big")).to_bytes(2, "big")
		encoded_source += packet + crc.to_bytes(2, "big")

		for index in range(0, len(encoded_source), SERIAL_MAX_DECODED_CHUNK):
			chunk = encoded_source[index:index + SERIAL_MAX_DECODED_CHUNK]
			marker = SERIAL_HDR_PKT if index == 0 else SERIAL_HDR_FRAG
			frame = marker + base64.b64encode(chunk) + b"\n"
			self._serial.write(frame)
		self._serial.flush()

	def read_event(self, timeout: float) -> tuple[str | None, bytes | None]:
		deadline = time.monotonic() + timeout
		while time.monotonic() < deadline:
			remaining = max(deadline - time.monotonic(), 0.01)
			self._serial.timeout = remaining
			line = self._serial.readline()
			if not line:
				continue

			if line.startswith(SERIAL_HDR_PKT) or line.startswith(SERIAL_HDR_FRAG):
				packet = self._consume_frame(line)
				if packet is not None:
					return "packet", packet
				continue

			return "console", line

		return None, None

	def _consume_frame(self, line: bytes) -> bytes | None:
		marker = line[:2]
		payload = line[2:].strip()
		decoded = base64.b64decode(payload, validate=True)

		if marker == SERIAL_HDR_PKT:
			if len(decoded) < 2:
				self._rx_payload.clear()
				self._rx_expected_len = None
				return None
			self._rx_expected_len = int.from_bytes(decoded[:2], "big")
			self._rx_payload = bytearray(decoded[2:])
		else:
			if self._rx_expected_len is None:
				return None
			self._rx_payload.extend(decoded)

		if self._rx_expected_len is None:
			return None
		if len(self._rx_payload) < self._rx_expected_len:
			return None
		if len(self._rx_payload) > self._rx_expected_len:
			self._rx_payload.clear()
			self._rx_expected_len = None
			raise ValueError("Received oversized SMP UART packet")

		packet = bytes(self._rx_payload)
		self._rx_payload.clear()
		self._rx_expected_len = None

		if crc16_itu_t(packet) != 0:
			raise ValueError("SMP UART CRC verification failed")

		return packet[:-2]


class EbpfMcumgrClient:
	def __init__(self, transport: SerialSmpTransport, timeout: float):
		self._transport = transport
		self._timeout = timeout
		self._seq = 0

	def load(self, bundle_path: Path, auto_enable: bool, chunk_size: int) -> dict[str, Any]:
		bundle = bundle_path.read_bytes()
		offset = 0
		response: dict[str, Any] = {}

		while offset < len(bundle):
			chunk = bundle[offset:offset + chunk_size]
			request: dict[str, Any] = {
				"off": offset,
				"data": chunk,
			}
			if offset == 0:
				request["len"] = len(bundle)
				if auto_enable:
					request["enable"] = True

			response = self._exchange(MGMT_OP_WRITE, ZEPHYR_MGMT_GRP_EBPF_CMD_LOAD, request)
			offset = int(response["off"])
			print(f"uploaded {offset}/{len(bundle)} bytes", file=sys.stderr)

		return response

	def enable(self, name: str) -> dict[str, Any]:
		return self._named_write(ZEPHYR_MGMT_GRP_EBPF_CMD_ENABLE, name)

	def disable(self, name: str) -> dict[str, Any]:
		return self._named_write(ZEPHYR_MGMT_GRP_EBPF_CMD_DISABLE, name)

	def unload(self, name: str) -> dict[str, Any]:
		return self._named_write(ZEPHYR_MGMT_GRP_EBPF_CMD_UNLOAD, name)

	def dump(self, name: str | None) -> dict[str, Any]:
		request = {} if name is None else {"name": name}
		return self._exchange(MGMT_OP_READ, ZEPHYR_MGMT_GRP_EBPF_CMD_DUMP, request)

	def map_read(self, name: str, map_name: str, key: bytes) -> dict[str, Any]:
		request = {
			"name": name,
			"map": map_name,
			"key": key,
		}
		return self._exchange(MGMT_OP_READ, ZEPHYR_MGMT_GRP_EBPF_CMD_MAP_READ, request)

	def watch_u32(
		self,
		name: str,
		map_name: str,
		key_value: int,
		interval: float,
		samples: int,
		endian: str,
	) -> None:
		key = key_value.to_bytes(4, endian, signed=False)
		previous: int | None = None

		for index in range(samples):
			response = self.map_read(name, map_name, key)
			value = response.get("value")
			if not isinstance(value, (bytes, bytearray)):
				raise RuntimeError("Map-read response does not contain a binary value")
			if len(value) != 4:
				raise RuntimeError(f"Expected 4-byte value for watch-u32, got {len(value)}")

			current = int.from_bytes(value, endian, signed=False)
			delta = 0 if previous is None else current - previous
			print(f"[{index + 1}] {map_name}[{key_value}] = {current} (+{delta})")
			previous = current

			if index + 1 < samples:
				time.sleep(interval)

	def follow_console(self, duration: float) -> None:
		deadline = time.monotonic() + duration
		while time.monotonic() < deadline:
			kind, payload = self._transport.read_event(deadline - time.monotonic())
			if kind == "console" and payload is not None:
				sys.stdout.write(payload.decode("utf-8", errors="replace"))
				sys.stdout.flush()
			elif kind == "packet" and payload is not None:
				header, response = parse_smp_packet(payload)
				print(
					json.dumps(
						{
							"unexpected_packet": {
								"header": header,
								"payload": normalize_for_json(response),
							}
						},
						indent=2,
					),
					file=sys.stderr,
				)

	def _named_write(self, command_id: int, name: str) -> dict[str, Any]:
		return self._exchange(MGMT_OP_WRITE, command_id, {"name": name})

	def _exchange(self, op: int, command_id: int, payload: dict[str, Any]) -> dict[str, Any]:
		seq = self._seq
		self._seq = (self._seq + 1) & 0xFF
		packet = build_smp_packet(op, command_id, seq, payload)
		self._transport.send_packet(packet)

		deadline = time.monotonic() + self._timeout
		while time.monotonic() < deadline:
			kind, incoming = self._transport.read_event(deadline - time.monotonic())
			if kind == "console" and incoming is not None:
				sys.stdout.write(incoming.decode("utf-8", errors="replace"))
				sys.stdout.flush()
				continue
			if kind != "packet" or incoming is None:
				continue

			header, response = parse_smp_packet(incoming)
			if header["seq"] != seq:
				continue

			expected_rsp = MGMT_OP_WRITE_RSP if op == MGMT_OP_WRITE else MGMT_OP_READ_RSP
			if header["op"] != expected_rsp:
				raise RuntimeError(f"Unexpected response op {header['op']}")
			if header["group"] != ZEPHYR_MGMT_GRP_EBPF:
				raise RuntimeError(f"Unexpected response group {header['group']}")

			if "err" in response:
				err = response["err"]
				raise McumgrError(
					f"Target rejected request: group={err.get('group')} rc={err.get('rc')}"
				)

			return response

		raise TimeoutError("Timed out waiting for MCUmgr response")


def build_argparser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--port", required=True, help="Serial port, for example COM7")
	parser.add_argument("--baud", type=int, default=115200, help="Serial baud rate")
	parser.add_argument("--timeout", type=float, default=5.0, help="Per-command timeout in seconds")

	subparsers = parser.add_subparsers(dest="command", required=True)

	load = subparsers.add_parser("load", help="Upload a bundle to the eBPF MCUmgr group")
	load.add_argument("--bundle", required=True, type=Path, help="Path to the runtime bundle")
	load.add_argument("--enable", action="store_true", help="Enable the bundle after the final chunk")
	load.add_argument("--chunk-size", type=int, default=128, help="Bundle payload bytes per MCUmgr load request")
	load.add_argument("--follow", type=float, default=0.0, help="Seconds to keep printing console output after the command")

	for name in ("enable", "disable", "unload"):
		command = subparsers.add_parser(name, help=f"Send the {name} command")
		command.add_argument("--name", default="thread_switch_probe", help="Bundle name")

	dump = subparsers.add_parser("dump", help="Dump bundle state from the eBPF MCUmgr group")
	dump.add_argument("--name", help="Optional bundle name filter")

	map_read = subparsers.add_parser("map-read", help="Read one map value through the eBPF MCUmgr group")
	map_read.add_argument("--name", default="thread_switch_probe", help="Bundle name")
	map_read.add_argument("--map", dest="map_name", default="counter_map", help="Map name")
	map_read.add_argument("--key-hex", default="00000000", help="Binary key bytes as hex")

	watch_u32 = subparsers.add_parser("watch-u32", help="Poll one 32-bit map entry repeatedly")
	watch_u32.add_argument("--name", default="thread_switch_probe", help="Bundle name")
	watch_u32.add_argument("--map", dest="map_name", default="counter_map", help="Map name")
	watch_u32.add_argument("--key-u32", type=int, default=0, help="Array/hash key interpreted as uint32")
	watch_u32.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds")
	watch_u32.add_argument("--samples", type=int, default=10, help="Number of samples to read")
	watch_u32.add_argument("--endian", choices=("little", "big"), default="little", help="Byte order used to decode the value")

	return parser


def main() -> int:
	args = build_argparser().parse_args()

	try:
		with SerialSmpTransport(args.port, args.baud, 0.25) as transport:
			client = EbpfMcumgrClient(transport, args.timeout)

			if args.command == "load":
				response = client.load(args.bundle, args.enable, args.chunk_size)
				print(json.dumps(normalize_for_json(response), indent=2))
				if args.follow > 0:
					client.follow_console(args.follow)
				return 0

			if args.command == "enable":
				response = client.enable(args.name)
			elif args.command == "disable":
				response = client.disable(args.name)
			elif args.command == "unload":
				response = client.unload(args.name)
			elif args.command == "map-read":
				response = client.map_read(args.name, args.map_name, bytes.fromhex(args.key_hex))
			elif args.command == "watch-u32":
				client.watch_u32(args.name, args.map_name, args.key_u32,
						 args.interval, args.samples, args.endian)
				return 0
			else:
				response = client.dump(args.name)

			print(json.dumps(normalize_for_json(response), indent=2))
			return 0
	except (CborDecodeError, McumgrError, OSError, RuntimeError, TimeoutError, ValueError) as exc:
		print(str(exc), file=sys.stderr)
		return 1


if __name__ == "__main__":
	sys.exit(main())