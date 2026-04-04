Bundle Runtime
##############

Files:

* :zephyr_file:`include/zephyr/ebpf/ebpf_bundle.h`
* :zephyr_file:`subsys/ebpf/bundle/ebpf_bundle.c`

Role
****

The bundle runtime is the ownership layer for loaded eBPF objects. It groups
maps and attachments into one named teardown unit so the loader can enable,
disable, and destroy them coherently.

Attachment Model
****************

Each runtime attachment owns:

* one RAM-resident :c:type:`ebpf_prog` descriptor,
* one copied instruction stream,
* one concrete target binding,
* membership in exactly one owning bundle.

Adding an attachment creates and attaches the program immediately, but it does
not enable dispatch until the bundle or attachment is enabled.

Owns
****

* bundle creation and destruction,
* bundle-owned map creation,
* bundle-owned attachment creation,
* coordinated enable and disable across all owned attachments,
* quiescent teardown for bundle-owned attachments.

Collaborates With
*****************

* :doc:`loader` instantiates bundles from image metadata.
* :doc:`program_lifecycle` supplies the runtime lifecycle used by each owned
  attachment program.
* :doc:`maps` supplies bundle map instances and ownership tracking.
* :doc:`dispatch_runtime` is involved indirectly when synchronous disable waits
  for active readers to drain.

Design Limits
*************

* The bundle is the coordinated teardown unit for runtime-loaded assets.
* Attachment destroy is intentionally stronger than plain disable because it
  waits for quiescence before freeing owned code and state.

.. _ebpf_bundle_image_format:

Bundle Image Format
*******************

The bundle image (``.bundle``) is a compact, flat binary that the loader
parses at runtime. It is produced offline by :command:`west ebpf build`,
which compiles a restricted-C probe source into a BPF ELF object
(:command:`clang -target bpf`) and then extracts only the sections the
runtime needs, discarding debug info, BTF, and other metadata. Compared to
loading standard ELF objects directly, this custom format is significantly
more lightweight and better suited for resource-constrained Zephyr embedded
targets where RAM, flash, and parsing complexity must be minimized.

Build Pipeline
==============

.. code-block:: text

   probe.c
     |
     | clang -target bpf -O2 -g -c
     v
   probe.elf  (ELF, EM_BPF)              <-- standard ELF, many sections
     |
     | west ebpf build  (scripts/west_commands/ebpf.py)
     |   _parse_elf():
     |     .maps           --> MapRecord[]
     |     ebpf.*/<hook>   --> AttachmentRecord[] (raw BPF insns)
     |     .rel*           --> RelocRecord[]
     |     .symtab         --> resolve names
     |   _pack_image():
     |     flatten into header + payload + auth
     v
   probe.bundle  (compact binary)        <-- only what the runtime needs

For example, the ``thread_switch_counter`` sample ELF is 5320 bytes with
26 sections; the resulting bundle is only 304 bytes.

ELF Sections Used vs Discarded
==============================

.. list-table::
   :header-rows: 1
   :widths: 35 10 55

   * - ELF Section
     - Kept
     - Purpose
   * - ``.maps``
     - Yes
     - Map definitions (type, key_size, value_size, max_entries)
   * - ``ebpf.sched/<hook>``, ``ebpf/<hook>``, etc.
     - Yes
     - BPF bytecode (program instructions)
   * - ``.relebpf.*``
     - Yes
     - Relocations (map references in BPF instructions)
   * - ``.symtab``
     - Yes
     - Symbol names for maps and program entry points
   * - ``.debug_*``
     - No
     - DWARF debug info, not needed at runtime
   * - ``.BTF`` / ``.BTF.ext``
     - No
     - BPF Type Format, used by Linux CO-RE, not used by Zephyr
   * - ``.text``
     - No
     - Empty for BPF objects (code lives in named sections)
   * - ``.strtab``
     - No
     - ELF string table, consumed during parsing only
   * - ``.llvm_addrsig``
     - No
     - LLVM address-significance table

Image Layout
============

All multi-byte fields are little-endian. All offsets are absolute byte
positions from the start of the image. The image is laid out as six
contiguous regions with no padding between them:

.. code-block:: text

   Offset          Size                    Region
   +-----------------------------------------------------------+
   | 0x00           64 bytes               Image Header        |
   +-----------------------------------------------------------+
   | header_size    map_count * 20         Map Records         |
   +-----------------------------------------------------------+
   |                attachment_count * 20   Attachment Records |
   +-----------------------------------------------------------+
   |                reloc_count * 12        Reloc Records      |
   +-----------------------------------------------------------+
   |                (variable)              BPF Instructions   |
   +-----------------------------------------------------------+
   |                strings_size            String Table       |
   +-----------------------------------------------------------+
   | auth_offset    auth_size               Auth Block         |
   +-----------------------------------------------------------+

Image Header (64 bytes)
=======================

Defined by ``ebpf_loader_image_header`` in
:zephyr_file:`subsys/ebpf/loader/ebpf_loader_internal.h`.

.. list-table::
   :header-rows: 1
   :widths: 12 8 16 64

   * - Offset
     - Size
     - Field
     - Description
   * - 0x00
     - 4
     - ``magic``
     - ``0x46504245`` (ASCII ``"EBPF"`` in little-endian)
   * - 0x04
     - 2
     - ``version``
     - Image format version (currently ``2``)
   * - 0x06
     - 2
     - ``header_size``
     - Size of this header in bytes (``64``)
   * - 0x08
     - 4
     - ``total_size``
     - Total image size including the auth block
   * - 0x0C
     - 4
     - ``auth_type``
     - ``0`` = none, ``1`` = CRC32, ``2`` = ECDSA-P256-SHA256
   * - 0x10
     - 4
     - ``ttl_ms``
     - Default time-to-live in milliseconds (``0`` = no expiry)
   * - 0x14
     - 4
     - ``bundle_name_offset``
     - Absolute offset to the NUL-terminated bundle name string
   * - 0x18
     - 4
     - ``map_count``
     - Number of map records
   * - 0x1C
     - 4
     - ``attachment_count``
     - Number of attachment records
   * - 0x20
     - 4
     - ``reloc_count``
     - Number of relocation records
   * - 0x24
     - 4
     - ``maps_offset``
     - Absolute offset to the first map record (``0`` if none)
   * - 0x28
     - 4
     - ``attachments_offset``
     - Absolute offset to the first attachment record
   * - 0x2C
     - 4
     - ``relocs_offset``
     - Absolute offset to the first relocation record
   * - 0x30
     - 4
     - ``strings_offset``
     - Absolute offset to the string table
   * - 0x34
     - 4
     - ``strings_size``
     - Size of the string table in bytes
   * - 0x38
     - 4
     - ``auth_offset``
     - Absolute offset to the auth block
   * - 0x3C
     - 4
     - ``auth_size``
     - Size of the auth block in bytes

Map Record (20 bytes each)
==========================

Defined by ``ebpf_loader_image_map``. One record per map declared with
the :c:macro:`EBPF_MAP` macro in the probe source.

.. list-table::
   :header-rows: 1
   :widths: 12 8 20 60

   * - Offset
     - Size
     - Field
     - Description
   * - +0x00
     - 4
     - ``name_offset``
     - Absolute offset to the NUL-terminated map name
   * - +0x04
     - 4
     - ``type``
     - Map type (e.g. ``0`` = ``EBPF_MAP_TYPE_ARRAY``)
   * - +0x08
     - 4
     - ``key_size``
     - Key size in bytes
   * - +0x0C
     - 4
     - ``value_size``
     - Value size in bytes
   * - +0x10
     - 4
     - ``max_entries``
     - Maximum number of entries

Attachment Record (20 bytes each)
=================================

Defined by ``ebpf_loader_image_attachment``. One record per eBPF
program function placed in a section named ``ebpf/<hook>``,
``ebpf.sched/<hook>``, ``ebpf.isr/<hook>``, or ``ebpf.pm/<hook>``.

.. list-table::
   :header-rows: 1
   :widths: 12 8 20 60

   * - Offset
     - Size
     - Field
     - Description
   * - +0x00
     - 4
     - ``name_offset``
     - Absolute offset to the NUL-terminated program name
   * - +0x04
     - 4
     - ``hook_name_offset``
     - Absolute offset to the NUL-terminated hook name
   * - +0x08
     - 4
     - ``prog_type``
     - ``0`` = generic, ``1`` = sched, ``2`` = ISR, ``3`` = PM
   * - +0x0C
     - 4
     - ``insns_offset``
     - Absolute offset to the first BPF instruction
   * - +0x10
     - 4
     - ``insn_cnt``
     - Number of 8-byte BPF instructions

Relocation Record (12 bytes each)
=================================

Defined by ``ebpf_loader_image_reloc``. The loader patches ``lddw``
instructions that reference maps. In the ELF, these appear as relocations
in ``.relebpf.*`` sections; the bundler converts them into this compact form.

.. list-table::
   :header-rows: 1
   :widths: 12 8 20 60

   * - Offset
     - Size
     - Field
     - Description
   * - +0x00
     - 4
     - ``attachment_index``
     - Index into the attachment records array
   * - +0x04
     - 4
     - ``insn_index``
     - Instruction index within the attachment's instruction stream
   * - +0x08
     - 4
     - ``map_index``
     - Index into the map records array

At load time, the loader resolves each relocation by writing the runtime map
pointer into the ``imm`` field of the target ``lddw`` instruction.

BPF Instructions
================

Raw BPF bytecode copied verbatim from the ELF program section. Each
instruction is 8 bytes (``lddw`` occupies 16 bytes as two consecutive
8-byte slots). The instruction stream is shared: each attachment record
points into this region via ``insns_offset`` and ``insn_cnt``.

String Table
============

A packed sequence of NUL-terminated UTF-8 strings. All ``*_offset`` fields
in the header and records point into this region. Strings are interned: each
unique string appears exactly once.

Auth Block
==========

Appended after the string table. The signed region covers all bytes from the
start of the image up to (but not including) the auth block itself.

.. list-table::
   :header-rows: 1
   :widths: 25 10 65

   * - Auth Type
     - Size
     - Content
   * - ``none`` (0)
     - 0
     - No auth block
   * - ``crc32`` (1)
     - 4
     - ``uint32_t crc32`` over bytes ``[0, auth_offset)``
   * - ``ecdsa-p256-sha256`` (2)
     - 68
     - ``uint32_t key_id`` + 64-byte raw ECDSA signature

Worked Example: thread_switch_counter
======================================

The ``thread_switch_counter`` sample produces a 304-byte bundle from this
probe source:

.. code-block:: c

   EBPF_MAP(counter_map, EBPF_MAP_TYPE_ARRAY, uint32_t, uint32_t, 1);

   EBPF_PROGRAM_SCHED("kernel/thread_switched_in")
   int count_thread_switches(void *ctx)
   {
       uint32_t key = 0;
       uint32_t *value = ebpf_map_lookup_elem(&counter_map, &key);
       if (value != 0) {
           *value += 1;
       }
       return 0;
   }

The resulting image layout is:

.. code-block:: text

   Offset  Size  Region
   ------  ----  --------------------------------------------------
   0x000     64  Image Header
                   magic        = 0x46504245 ("EBPF")
                   version      = 2
                   total_size   = 304
                   auth_type    = 1 (CRC32)
                   map_count    = 1
                   attachment_count = 1
                   reloc_count  = 1
   0x040     20  Map Records [1]
                   "counter_map" type=ARRAY key=4 val=4 max=1
   0x054     20  Attachment Records [1]
                   "count_thread_switches"
                   hook="kernel/thread_switched_in" prog_type=SCHED
                   insns_offset=0x74 insn_cnt=13
   0x068     12  Reloc Records [1]
                   attachment[0].insn[4] -> map[0]
   0x074    104  BPF Instructions (13 insns)
                   insn[ 4]: lddw r1, 0x0  <-- patched by reloc
                   insn[ 6]: call map_lookup_elem
                   insn[12]: exit
   0x0DC     80  String Table
                   +0  "thread_switch_probe"
                   +20 "counter_map"
                   +32 "count_thread_switches"
                   +54 "kernel/thread_switched_in"
   0x12C      4  Auth Block
                   CRC32 = 0xd2dcf503
