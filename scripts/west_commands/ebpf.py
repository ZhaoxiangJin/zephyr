# SPDX-FileCopyrightText: Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

import argparse
import dataclasses
import pathlib
import struct
import subprocess
import tempfile
import zlib

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from west.commands import WestCommand

from zephyr_ext_common import ZEPHYR_BASE

IMAGE_HEADER_FORMAT = "<IHH14I"
IMAGE_MAP_FORMAT = "<IIIII"
IMAGE_ATTACHMENT_FORMAT = "<IIIII"
IMAGE_RELOC_FORMAT = "<III"
IMAGE_AUTH_CRC32_FORMAT = "<I"
IMAGE_AUTH_ECDSA_P256_FORMAT = "<I64s"
MAP_DEF_FORMAT = "<IIII"

AUTH_TYPE_NONE = 0
AUTH_TYPE_CRC32 = 1
AUTH_TYPE_ECDSA_P256_SHA256 = 2

PROG_TYPE_GENERIC = 0
PROG_TYPE_SCHED = 1
PROG_TYPE_ISR = 2
PROG_TYPE_PM = 3

IMAGE_MAGIC = 0x46504245
IMAGE_VERSION = 1

PROGRAM_SECTION_PREFIXES = {
	"ebpf/": PROG_TYPE_GENERIC,
	"ebpf.generic/": PROG_TYPE_GENERIC,
	"ebpf.sched/": PROG_TYPE_SCHED,
	"ebpf.isr/": PROG_TYPE_ISR,
	"ebpf.pm/": PROG_TYPE_PM,
}


@dataclasses.dataclass
class MapRecord:
	name: str
	type: int
	key_size: int
	value_size: int
	max_entries: int
	offset: int
	symbol_index: int


@dataclasses.dataclass
class RelocRecord:
	attachment_index: int
	insn_index: int
	map_index: int


@dataclasses.dataclass
class AttachmentRecord:
	name: str
	hook_name: str
	prog_type: int
	insns: bytes
	relocs: list[RelocRecord]


class EbpfBundleBuilder:
	def __init__(self, command):
		self.command = command

	def build(self, args):
		input_path = pathlib.Path(args.input).resolve()
		output_path = pathlib.Path(args.output).resolve()
		self._validate_auth_args(args)

		if input_path.suffix.lower() == ".c":
			with tempfile.TemporaryDirectory(prefix="zephyr-ebpf-") as tmpdir:
				obj_path = pathlib.Path(tmpdir) / (input_path.stem + ".o")
				self._compile_source(args, input_path, obj_path)
				if args.emit_elf:
					emit_path = pathlib.Path(args.emit_elf).resolve()
					emit_path.parent.mkdir(parents=True, exist_ok=True)
					emit_path.write_bytes(obj_path.read_bytes())
				maps, attachments = self._parse_elf(obj_path)
		else:
			maps, attachments = self._parse_elf(input_path)

		image = self._pack_image(
			bundle_name=args.bundle_name or input_path.stem,
			ttl_ms=args.ttl_ms,
			auth_type=args.auth,
			key_id=args.key_id,
			maps=maps,
			attachments=attachments,
			args=args,
		)

		output_path.parent.mkdir(parents=True, exist_ok=True)
		output_path.write_bytes(image)
		self.command.inf(f"wrote {output_path}")

	def _validate_auth_args(self, args):
		if args.auth == AUTH_TYPE_ECDSA_P256_SHA256:
			if bool(args.signing_key) == bool(args.signature_file):
				self.command.die(
					"ecdsa-p256-sha256 authentication requires exactly one of "
					"--signing-key or --signature-file"
				)
		else:
			if args.signing_key or args.signature_file:
				self.command.die("signature inputs require --auth ecdsa-p256-sha256")
			if args.key_id != 0:
				self.command.die("--key-id is only valid with --auth ecdsa-p256-sha256")

	def _compile_source(self, args, input_path, obj_path):
		command = [
			args.clang,
			"-target",
			"bpf",
			"-O2",
			"-g",
			"-c",
			str(input_path),
			"-o",
			str(obj_path),
			"-I",
			str(ZEPHYR_BASE / "include"),
		]

		for include_dir in args.include_dir:
			command.extend(["-I", include_dir])

		for define in args.define:
			command.extend(["-D", define])

		command.extend(args.clang_opt)

		result = subprocess.run(command, capture_output=True, text=True, check=False)
		if result.returncode != 0:
			message = result.stderr.strip() or result.stdout.strip() or "clang failed"
			self.command.die(message)

	def _parse_elf(self, elf_path):
		with elf_path.open("rb") as fp:
			elf = ELFFile(fp)
			if elf["e_machine"] != "EM_BPF":
				self.command.die(f"{elf_path} is not an eBPF ELF object")
			if not elf.little_endian:
				self.command.die("only little-endian eBPF ELF objects are supported")

			symtab = self._find_symtab(elf)
			maps = self._collect_maps(elf, symtab)
			attachments = self._collect_attachments(elf, symtab, maps)
			if not attachments:
				self.command.die("no eBPF program sections were found; expected sections like 'ebpf/<hook>'")

			return maps, attachments

	def _find_symtab(self, elf):
		for section in elf.iter_sections():
			if isinstance(section, SymbolTableSection) and section.name == ".symtab":
				return section

		self.command.die("ELF object is missing .symtab")

	def _collect_maps(self, elf, symtab):
		maps_section = elf.get_section_by_name(".maps")
		if maps_section is None:
			return []

		maps_section_index = None
		for section_index, section in enumerate(elf.iter_sections()):
			if section.name == ".maps":
				maps_section_index = section_index
				break

		if maps_section_index is None:
			self.command.die("failed to resolve the .maps section index")

		maps_data = maps_section.data()
		maps = []
		for symbol_index, symbol in enumerate(symtab.iter_symbols()):
			if symbol["st_shndx"] != maps_section_index:
				continue
			if symbol["st_info"]["type"] != "STT_OBJECT" or not symbol.name:
				continue

			offset = int(symbol["st_value"])
			size = int(symbol["st_size"])
			if size < struct.calcsize(MAP_DEF_FORMAT):
				self.command.die(f"map '{symbol.name}' has unsupported size {size}")

			raw = maps_data[offset:offset + struct.calcsize(MAP_DEF_FORMAT)]
			map_type, key_size, value_size, max_entries = struct.unpack(MAP_DEF_FORMAT, raw)
			maps.append(MapRecord(
				name=symbol.name,
				type=map_type,
				key_size=key_size,
				value_size=value_size,
				max_entries=max_entries,
				offset=offset,
				symbol_index=symbol_index,
			))

		maps.sort(key=lambda record: record.offset)
		return maps

	def _collect_attachments(self, elf, symtab, maps):
		map_index_by_symbol = {
			record.symbol_index: index for index, record in enumerate(maps)
		}
		attachments = []

		for section_index, section in enumerate(elf.iter_sections()):
			parsed = self._parse_program_section_name(section.name)
			if parsed is None:
				continue

			prog_type, hook_name = parsed
			insns = section.data()
			if len(insns) == 0 or (len(insns) % 8) != 0:
				self.command.die(f"program section '{section.name}' has invalid instruction payload size {len(insns)}")

			attachment_name = self._find_program_name(symtab, section_index)
			relocs = self._collect_program_relocations(
				elf=elf,
				section_index=section_index,
				insn_count=len(insns) // 8,
				map_index_by_symbol=map_index_by_symbol,
			)

			attachments.append(AttachmentRecord(
				name=attachment_name,
				hook_name=hook_name,
				prog_type=prog_type,
				insns=insns,
				relocs=relocs,
			))

		return attachments

	def _parse_program_section_name(self, section_name):
		for prefix, prog_type in PROGRAM_SECTION_PREFIXES.items():
			if section_name.startswith(prefix):
				hook_name = section_name[len(prefix):]
				if not hook_name:
					self.command.die(f"program section '{section_name}' is missing a hook name")
				return prog_type, hook_name

		return None

	def _find_program_name(self, symtab, section_index):
		candidates = []
		for symbol in symtab.iter_symbols():
			if symbol["st_shndx"] != section_index:
				continue
			if symbol["st_info"]["type"] != "STT_FUNC":
				continue
			candidates.append(symbol)

		zero_offset = [symbol for symbol in candidates if int(symbol["st_value"]) == 0 and symbol.name]
		if len(zero_offset) == 1:
			return zero_offset[0].name

		if len(candidates) == 1 and candidates[0].name:
			return candidates[0].name

		self.command.die(f"could not resolve a unique entry symbol for program section index {section_index}")

	def _collect_program_relocations(self, elf, section_index, insn_count, map_index_by_symbol):
		relocs = []

		for section in elf.iter_sections():
			if not isinstance(section, RelocationSection):
				continue
			if int(section["sh_info"]) != section_index:
				continue

			linked_symtab = elf.get_section(section["sh_link"])
			for reloc in section.iter_relocations():
				symbol_index = reloc["r_info_sym"]
				symbol = linked_symtab.get_symbol(symbol_index)
				if symbol_index not in map_index_by_symbol:
					self.command.die(
						f"unsupported relocation against symbol '{symbol.name}' in program section index {section_index}"
					)

				insn_index = int(reloc["r_offset"]) // 8
				if insn_index >= insn_count:
					self.command.die(f"relocation at offset {reloc['r_offset']} points beyond the instruction stream")

				relocs.append(RelocRecord(
					attachment_index=0,
					insn_index=insn_index,
					map_index=map_index_by_symbol[symbol_index],
				))
				self.command.dbg(
					f"relocated program instruction {insn_index} against map '{symbol.name}'"
				)

		return relocs

	def _auth_block_size(self, auth_type):
		if auth_type == AUTH_TYPE_NONE:
			return 0
		if auth_type == AUTH_TYPE_CRC32:
			return struct.calcsize(IMAGE_AUTH_CRC32_FORMAT)
		if auth_type == AUTH_TYPE_ECDSA_P256_SHA256:
			return struct.calcsize(IMAGE_AUTH_ECDSA_P256_FORMAT)

		self.command.die(f"unsupported auth type {auth_type}")

	def _build_auth_block(self, auth_type, signed_image, key_id, args):
		if auth_type == AUTH_TYPE_NONE:
			return b""

		if auth_type == AUTH_TYPE_CRC32:
			return struct.pack(IMAGE_AUTH_CRC32_FORMAT, zlib.crc32(signed_image) & 0xFFFFFFFF)

		if auth_type != AUTH_TYPE_ECDSA_P256_SHA256:
			self.command.die(f"unsupported auth type {auth_type}")

		signature = self._get_ecdsa_signature(signed_image, args)
		return struct.pack(IMAGE_AUTH_ECDSA_P256_FORMAT, key_id, signature)

	def _get_ecdsa_signature(self, signed_image, args):
		if args.signature_file:
			raw = pathlib.Path(args.signature_file).resolve().read_bytes()
		else:
			raw = self._sign_with_openssl(signed_image, args)

		if len(raw) == 64:
			return raw

		return self._ecdsa_der_to_raw(raw)

	def _sign_with_openssl(self, signed_image, args):
		with tempfile.TemporaryDirectory(prefix="zephyr-ebpf-sign-") as tmpdir:
			data_path = pathlib.Path(tmpdir) / "bundle.signed"
			sig_path = pathlib.Path(tmpdir) / "bundle.sig"
			data_path.write_bytes(signed_image)

			command = [
				args.openssl,
				"dgst",
				"-sha256",
				"-sign",
				str(pathlib.Path(args.signing_key).resolve()),
				"-out",
				str(sig_path),
				str(data_path),
			]
			result = subprocess.run(command, capture_output=True, text=True, check=False)
			if result.returncode != 0:
				message = result.stderr.strip() or result.stdout.strip() or "openssl signing failed"
				self.command.die(message)

			return sig_path.read_bytes()

	def _asn1_read_length(self, data, offset):
		if offset >= len(data):
			self.command.die("invalid ASN.1 signature: truncated length")

		first = data[offset]
		offset += 1
		if (first & 0x80) == 0:
			return first, offset

		count = first & 0x7F
		if count == 0 or (offset + count) > len(data):
			self.command.die("invalid ASN.1 signature: malformed long-form length")

		length = 0
		for _ in range(count):
			length = (length << 8) | data[offset]
			offset += 1

		return length, offset

	def _asn1_read_integer(self, data, offset):
		if offset >= len(data) or data[offset] != 0x02:
			self.command.die("invalid ASN.1 signature: expected INTEGER")

		length, offset = self._asn1_read_length(data, offset + 1)
		end = offset + length
		if end > len(data):
			self.command.die("invalid ASN.1 signature: truncated INTEGER")

		value = data[offset:end]
		if not value:
			self.command.die("invalid ASN.1 signature: empty INTEGER")

		while len(value) > 1 and value[0] == 0x00:
			value = value[1:]

		if len(value) > 32:
			self.command.die("invalid ASN.1 signature: INTEGER exceeds 32 bytes")

		return value.rjust(32, b"\x00"), end

	def _ecdsa_der_to_raw(self, der):
		if len(der) < 8 or der[0] != 0x30:
			self.command.die("ECDSA signature file must contain either 64-byte raw data or ASN.1 DER")

		seq_len, offset = self._asn1_read_length(der, 1)
		if offset + seq_len != len(der):
			self.command.die("invalid ASN.1 signature: sequence length mismatch")

		r_value, offset = self._asn1_read_integer(der, offset)
		s_value, offset = self._asn1_read_integer(der, offset)
		if offset != len(der):
			self.command.die("invalid ASN.1 signature: trailing data")

		return r_value + s_value

	def _pack_image(self, bundle_name, ttl_ms, auth_type, key_id, maps, attachments, args):
		strings = bytearray()
		map_records = []
		attachment_records = []
		reloc_records = []
		insn_blobs = bytearray()

		def intern_string(value):
			encoded = value.encode("utf-8") + b"\x00"
			offset = len(strings)
			strings.extend(encoded)
			return offset

		bundle_name_rel = intern_string(bundle_name)

		for map_record in maps:
			map_records.append({
				"name_rel": intern_string(map_record.name),
				"type": map_record.type,
				"key_size": map_record.key_size,
				"value_size": map_record.value_size,
				"max_entries": map_record.max_entries,
			})

		for attachment_index, attachment in enumerate(attachments):
			insns_offset_rel = len(insn_blobs)
			insn_blobs.extend(attachment.insns)
			attachment_records.append({
				"name_rel": intern_string(attachment.name),
				"hook_name_rel": intern_string(attachment.hook_name),
				"prog_type": attachment.prog_type,
				"insns_offset_rel": insns_offset_rel,
				"insn_cnt": len(attachment.insns) // 8,
			})

			for reloc in attachment.relocs:
				reloc_records.append({
					"attachment_index": attachment_index,
					"insn_index": reloc.insn_index,
					"map_index": reloc.map_index,
				})

		header_size = struct.calcsize(IMAGE_HEADER_FORMAT)
		maps_offset = header_size if map_records else 0
		attachments_offset = maps_offset + (len(map_records) * struct.calcsize(IMAGE_MAP_FORMAT))
		relocs_offset = attachments_offset + (len(attachment_records) * struct.calcsize(IMAGE_ATTACHMENT_FORMAT))
		insns_offset = relocs_offset + (len(reloc_records) * struct.calcsize(IMAGE_RELOC_FORMAT))
		strings_offset = insns_offset + len(insn_blobs)

		payload = bytearray()
		for record in map_records:
			payload.extend(struct.pack(
				IMAGE_MAP_FORMAT,
				strings_offset + record["name_rel"],
				record["type"],
				record["key_size"],
				record["value_size"],
				record["max_entries"],
			))

		for record in attachment_records:
			payload.extend(struct.pack(
				IMAGE_ATTACHMENT_FORMAT,
				strings_offset + record["name_rel"],
				strings_offset + record["hook_name_rel"],
				record["prog_type"],
				insns_offset + record["insns_offset_rel"],
				record["insn_cnt"],
			))

		for record in reloc_records:
			payload.extend(struct.pack(
				IMAGE_RELOC_FORMAT,
				record["attachment_index"],
				record["insn_index"],
				record["map_index"],
			))

		payload.extend(insn_blobs)
		payload.extend(strings)

		auth_size = self._auth_block_size(auth_type)
		auth_offset = header_size + len(payload)
		total_size = auth_offset + auth_size

		signed_image = struct.pack(
			IMAGE_HEADER_FORMAT,
			IMAGE_MAGIC,
			IMAGE_VERSION,
			header_size,
			total_size,
			auth_type,
			ttl_ms,
			strings_offset + bundle_name_rel,
			len(map_records),
			len(attachment_records),
			len(reloc_records),
			maps_offset,
			attachments_offset if attachment_records else 0,
			relocs_offset if reloc_records else 0,
			strings_offset,
			len(strings),
			auth_offset,
			auth_size,
		) + payload

		auth_block = self._build_auth_block(auth_type, signed_image, key_id, args)
		if len(auth_block) != auth_size:
			self.command.die(
				f"internal auth size mismatch: expected {auth_size} bytes, got {len(auth_block)}"
			)

		return signed_image + auth_block


class Ebpf(WestCommand):
	def __init__(self):
		super().__init__(
			"ebpf",
			"",
			description="Build Zephyr eBPF probe bundles",
			accepts_unknown_args=False,
		)

	def do_add_parser(self, parser_adder):
		parser = parser_adder.add_parser(
			self.name,
			description=self.description,
			formatter_class=argparse.RawDescriptionHelpFormatter,
		)

		subparsers = parser.add_subparsers(help="sub-command to run", required=True)
		build_parser = subparsers.add_parser(
			"build",
			help="compile or pack a Zephyr eBPF probe into a runtime bundle image",
			formatter_class=argparse.RawDescriptionHelpFormatter,
			description=(
				"Compile restricted C probe sources or pack existing eBPF ELF objects "
				"into the experimental Zephyr runtime-loader image format.\n\n"
				"Program sections must be named like 'ebpf/<hook>', 'ebpf.sched/<hook>', "
				"'ebpf.isr/<hook>', or 'ebpf.pm/<hook>'."
			),
		)
		build_parser.set_defaults(handler=self._do_build)
		build_parser.add_argument("input", help="input .c, .o, or .elf file")
		build_parser.add_argument("-o", "--output", required=True,
					 help="output runtime bundle image path")
		build_parser.add_argument("-n", "--bundle-name", default=None,
					 help="bundle name embedded in the image (default: input basename)")
		build_parser.add_argument("--ttl-ms", type=int, default=0,
					 help="default bundle TTL in milliseconds")
		build_parser.add_argument("--auth",
					 choices=["none", "crc32", "ecdsa-p256-sha256"],
					 default="crc32",
					 help="image authentication mode")
		build_parser.add_argument("--signing-key", default=None,
					 help="PEM private key used by openssl for ecdsa-p256-sha256 auth")
		build_parser.add_argument("--signature-file", default=None,
					 help="precomputed 64-byte raw or ASN.1 DER ECDSA signature")
		build_parser.add_argument("--openssl", default="openssl",
					 help="openssl executable used for signing")
		build_parser.add_argument("--key-id", type=int, default=0,
					 help="signing key identifier embedded in the auth block")
		build_parser.add_argument("--clang", default="clang",
					 help="clang executable to use when compiling a .c input")
		build_parser.add_argument("-I", "--include-dir", action="append", default=[],
					 help="additional include directories for clang")
		build_parser.add_argument("-D", "--define", action="append", default=[],
					 help="additional preprocessor definitions for clang")
		build_parser.add_argument("--clang-opt", action="append", default=[],
					 help="extra option to pass through to clang")
		build_parser.add_argument("--emit-elf", default=None,
					 help="optional path to keep the intermediate ELF object when compiling .c")

		return parser

	def do_run(self, args, ignored):
		args.handler(args)

	def _do_build(self, args):
		auth_map = {
			"none": AUTH_TYPE_NONE,
			"crc32": AUTH_TYPE_CRC32,
			"ecdsa-p256-sha256": AUTH_TYPE_ECDSA_P256_SHA256,
		}
		args.auth = auth_map[args.auth]
		builder = EbpfBundleBuilder(self)
		builder.build(args)
