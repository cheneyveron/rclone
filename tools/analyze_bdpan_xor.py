#!/usr/bin/env python3
"""Analyze bdpan's embedded credential XOR routine without revealing credentials.

The script reads a stripped Go ELF binary, recovers function boundaries from
``.gopclntab``, and asks GNU objdump for instruction metadata.  Its reporter is
deliberately allowlist-only: it never prints disassembly, operands, immediate
values, strings, raw data, decoded buffers, or credential-derived hashes.

Only structural facts are reported, such as function sizes, code hashes,
instruction counts, loop evidence, and whether standalone or compiler-inlined
credential helpers lead to the XOR decoder.
"""

from __future__ import annotations

import argparse
import bisect
import dataclasses
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Iterable


class AnalysisError(Exception):
    """AnalysisError describes a safe, non-sensitive analysis failure."""


@dataclasses.dataclass(frozen=True)
class Section:
    """Section is one ELF section needed by the analyzer."""

    name: str
    section_type: int
    flags: int
    address: int
    offset: int
    size: int

    def contains_address(self, address: int) -> bool:
        """contains_address reports whether address belongs to the section."""

        return self.address <= address < self.address + self.size


@dataclasses.dataclass(frozen=True)
class GoFunction:
    """GoFunction is a function recovered from the Go PC/line table."""

    name: str
    start: int
    end: int


@dataclasses.dataclass(frozen=True)
class Instruction:
    """Instruction contains only transient disassembly used for classification."""

    address: int
    mnemonic: str
    operands: str


class ELFImage:
    """ELFImage parses the small ELF subset required by the analyzer."""

    _ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
    _SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")

    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            self.data = path.read_bytes()
        except OSError as error:
            raise AnalysisError("unable to read the input binary") from error

        if len(self.data) < self._ELF_HEADER.size:
            raise AnalysisError("input is too small to be an ELF binary")

        header = self._ELF_HEADER.unpack_from(self.data)
        ident = header[0]
        if ident[:4] != b"\x7fELF":
            raise AnalysisError("input is not an ELF binary")
        if ident[4] != 2 or ident[5] != 1:
            raise AnalysisError("only 64-bit little-endian ELF binaries are supported")

        self.machine = header[2]
        section_offset = header[6]
        section_entry_size = header[11]
        section_count = header[12]
        section_names_index = header[13]

        if section_entry_size != self._SECTION_HEADER.size:
            raise AnalysisError("unsupported ELF section-header size")
        if section_count == 0 or section_count > 100_000:
            raise AnalysisError("invalid ELF section count")
        if section_names_index >= section_count:
            raise AnalysisError("invalid ELF section-name table index")

        raw_sections: list[tuple[int, ...]] = []
        for index in range(section_count):
            offset = section_offset + index * section_entry_size
            if offset + section_entry_size > len(self.data):
                raise AnalysisError("ELF section table is truncated")
            raw_sections.append(self._SECTION_HEADER.unpack_from(self.data, offset))

        names_header = raw_sections[section_names_index]
        names_offset, names_size = names_header[4], names_header[5]
        names = self._slice(names_offset, names_size, "ELF section-name table")

        self.sections: dict[str, Section] = {}
        for raw in raw_sections:
            name_offset, section_type, flags, address, offset, size, _, _, _, _ = raw
            name = self._cstring(names, name_offset)
            if not name:
                continue
            if section_type != 8 and offset + size > len(self.data):
                raise AnalysisError("ELF section extends past end of file")
            self.sections[name] = Section(name, section_type, flags, address, offset, size)

    def _slice(self, offset: int, size: int, label: str) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise AnalysisError(f"{label} is outside the input binary")
        return self.data[offset : offset + size]

    @staticmethod
    def _cstring(data: bytes, offset: int) -> str:
        if offset < 0 or offset >= len(data):
            return ""
        end = data.find(b"\0", offset)
        if end < 0:
            return ""
        return data[offset:end].decode("utf-8", errors="replace")

    def section_data(self, name: str) -> bytes:
        """section_data returns a named section's bytes."""

        section = self.sections.get(name)
        if section is None:
            raise AnalysisError(f"required ELF section is missing: {name}")
        if section.section_type == 8:
            raise AnalysisError(f"ELF section has no file-backed data: {name}")
        return self._slice(section.offset, section.size, name)

    def address_bytes(self, start: int, end: int) -> bytes:
        """address_bytes maps a virtual-address interval to file bytes."""

        if end <= start:
            raise AnalysisError("invalid function address interval")
        for section in self.sections.values():
            if section.address <= start and end <= section.address + section.size:
                offset = section.offset + start - section.address
                return self._slice(offset, end - start, "function body")
        raise AnalysisError("function body is not contained in one ELF section")

    def section_for_address(self, address: int) -> Section | None:
        """section_for_address returns the section containing address."""

        for section in self.sections.values():
            if section.contains_address(address):
                return section
        return None


class GoPCLNTable:
    """GoPCLNTable recovers Go 1.18+ functions from .gopclntab."""

    _MAGIC_GO118 = 0xFFFFFFF0
    _MAGIC_GO120 = 0xFFFFFFF1

    def __init__(self, image: ELFImage) -> None:
        self.image = image
        self.section = image.sections.get(".gopclntab")
        if self.section is None:
            raise AnalysisError("Go .gopclntab section is missing")
        self.data = image.section_data(".gopclntab")
        self.functions = self._parse()
        self._starts = [function.start for function in self.functions]
        self._by_start = {function.start: function for function in self.functions}

    def _parse(self) -> list[GoFunction]:
        if len(self.data) < 8 + 8 * 8:
            raise AnalysisError("Go PC/line table is truncated")

        magic = struct.unpack_from("<I", self.data, 0)[0]
        if magic not in {self._MAGIC_GO118, self._MAGIC_GO120}:
            raise AnalysisError("only Go 1.18+ PC/line tables are supported")
        if self.data[4:6] != b"\0\0":
            raise AnalysisError("invalid Go PC/line table header")

        pointer_size = self.data[7]
        if pointer_size not in {4, 8}:
            raise AnalysisError("unsupported Go pointer size")

        pointer_format = "<I" if pointer_size == 4 else "<Q"

        def word(index: int) -> int:
            offset = 8 + index * pointer_size
            if offset + pointer_size > len(self.data):
                raise AnalysisError("Go PC/line table header is truncated")
            return struct.unpack_from(pointer_format, self.data, offset)[0]

        function_count = word(0)
        function_names_offset = word(3)
        function_data_offset = word(7)
        if function_count == 0 or function_count > 10_000_000:
            raise AnalysisError("invalid Go function count")
        if function_names_offset >= len(self.data) or function_data_offset >= len(self.data):
            raise AnalysisError("Go PC/line table offsets are invalid")

        text = self.image.sections.get(".text")
        if text is None:
            raise AnalysisError("ELF .text section is missing")

        table_size = function_count * 8 + 4
        if function_data_offset + table_size > len(self.data):
            raise AnalysisError("Go function table is truncated")

        functions: list[GoFunction] = []
        for index in range(function_count):
            entry_offset, data_offset = struct.unpack_from(
                "<II", self.data, function_data_offset + index * 8
            )
            next_entry_offset = struct.unpack_from(
                "<I", self.data, function_data_offset + (index + 1) * 8
            )[0]
            metadata_offset = function_data_offset + data_offset
            if metadata_offset + 8 > len(self.data):
                raise AnalysisError("Go function metadata is outside the PC/line table")
            name_offset = struct.unpack_from("<i", self.data, metadata_offset + 4)[0]
            name_address = function_names_offset + name_offset
            if name_address < 0 or name_address >= len(self.data):
                raise AnalysisError("Go function name is outside the PC/line table")
            name_end = self.data.find(b"\0", name_address)
            if name_end < 0:
                raise AnalysisError("Go function name is unterminated")
            name = self.data[name_address:name_end].decode("utf-8", errors="replace")
            start = text.address + entry_offset
            end = text.address + next_entry_offset
            if start < text.address or end > text.address + text.size or end <= start:
                raise AnalysisError("Go function address is outside .text")
            functions.append(GoFunction(name, start, end))

        return functions

    def find_suffix(self, suffix: str) -> GoFunction | None:
        """find_suffix finds the unique function whose name ends with suffix."""

        matches = [function for function in self.functions if function.name.endswith(suffix)]
        if len(matches) > 1:
            raise AnalysisError(f"multiple Go functions match the safe suffix {suffix}")
        return matches[0] if matches else None

    def has_name_hint(self, suffix: str) -> bool:
        """has_name_hint reports whether an inline function name is retained."""

        return suffix.encode("utf-8") + b"\0" in self.data

    def by_start(self, address: int) -> GoFunction | None:
        """by_start returns the function beginning at address."""

        return self._by_start.get(address)

    def containing(self, address: int) -> GoFunction | None:
        """containing returns the function whose interval contains address."""

        index = bisect.bisect_right(self._starts, address) - 1
        if index < 0:
            return None
        function = self.functions[index]
        return function if address < function.end else None


class Disassembler:
    """Disassembler obtains instruction structure without exposing operands."""

    _INSTRUCTION = re.compile(
        r"^\s*([0-9a-fA-F]+):\s+([A-Za-z][A-Za-z0-9.]*)\s*(.*?)\s*$"
    )
    _HEX_TARGET = re.compile(r"(?:0x)?([0-9a-fA-F]+)")
    _COMMENT_TARGET = re.compile(r"#\s*(?:0x)?([0-9a-fA-F]+)")

    def __init__(self, executable: str, binary: Path) -> None:
        self.executable = executable
        self.binary = binary

    def function(self, function: GoFunction) -> list[Instruction]:
        """function disassembles one function and keeps output private."""

        command = [
            self.executable,
            "-d",
            "--no-show-raw-insn",
            f"--start-address=0x{function.start:x}",
            f"--stop-address=0x{function.end:x}",
            os.fspath(self.binary),
        ]
        try:
            result = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AnalysisError("objdump failed while analyzing a function") from error
        if result.returncode != 0:
            raise AnalysisError("objdump rejected the input binary")

        instructions: list[Instruction] = []
        for line in result.stdout.splitlines():
            match = self._INSTRUCTION.match(line)
            if match is None:
                continue
            instructions.append(
                Instruction(
                    address=int(match.group(1), 16),
                    mnemonic=match.group(2).lower(),
                    operands=match.group(3),
                )
            )
        if not instructions:
            raise AnalysisError("objdump produced no instructions for a recovered function")
        return instructions

    @classmethod
    def direct_target(cls, instruction: Instruction) -> int | None:
        """direct_target returns a direct branch/call target when present."""

        operands = instruction.operands.lstrip()
        if not operands or operands.startswith("*"):
            return None
        match = cls._HEX_TARGET.match(operands)
        return int(match.group(1), 16) if match else None

    @classmethod
    def referenced_address(cls, instruction: Instruction) -> int | None:
        """referenced_address obtains objdump's resolved RIP-relative target."""

        match = cls._COMMENT_TARGET.search(instruction.operands)
        return int(match.group(1), 16) if match else None


def is_xor(mnemonic: str) -> bool:
    """is_xor reports whether mnemonic denotes an XOR operation."""

    return mnemonic.startswith(("xor", "pxor", "vpxor")) or mnemonic in {"eor", "eors"}


def is_zeroing_xor(instruction: Instruction) -> bool:
    """is_zeroing_xor identifies the common x86 register-zeroing idiom."""

    if not instruction.mnemonic.startswith(("xor", "pxor", "vpxor")):
        return False
    operands = [operand.strip() for operand in instruction.operands.split(",")]
    return len(operands) == 2 and operands[0] == operands[1]


def is_division(mnemonic: str) -> bool:
    """is_division reports whether mnemonic can implement key-index modulo."""

    return mnemonic.startswith(("div", "idiv", "udiv", "sdiv"))


def is_branch(mnemonic: str) -> bool:
    """is_branch reports whether mnemonic is a control-flow branch."""

    return mnemonic.startswith("j") or mnemonic in {
        "b",
        "b.eq",
        "b.ne",
        "b.lt",
        "b.le",
        "b.gt",
        "b.ge",
        "cbz",
        "cbnz",
    }


def is_call(mnemonic: str) -> bool:
    """is_call reports whether mnemonic is a direct-call instruction."""

    return mnemonic in {"call", "callq", "bl"}


def find_xor_loops(
    disassembler: Disassembler,
    function: GoFunction,
    instructions: list[Instruction],
) -> list[dict[str, int | bool]]:
    """find_xor_loops summarizes backward loops that perform data XOR."""

    backward_intervals: set[tuple[int, int]] = set()
    for branch in instructions:
        if not is_branch(branch.mnemonic):
            continue
        target = disassembler.direct_target(branch)
        if target is None or not function.start <= target < branch.address:
            continue
        backward_intervals.add((target, branch.address))

    selected_intervals: set[tuple[int, int]] = set()
    for instruction in instructions:
        if not is_xor(instruction.mnemonic) or is_zeroing_xor(instruction):
            continue
        enclosing = [
            interval
            for interval in backward_intervals
            if interval[0] <= instruction.address <= interval[1]
        ]
        if enclosing:
            selected_intervals.add(
                min(enclosing, key=lambda interval: interval[1] - interval[0])
            )

    loops: list[dict[str, int | bool]] = []
    for target, end in sorted(selected_intervals):
        body = [
            instruction
            for instruction in instructions
            if target <= instruction.address <= end
        ]
        data_xor_count = sum(
            is_xor(instruction.mnemonic) and not is_zeroing_xor(instruction)
            for instruction in body
        )
        division_count = sum(
            is_division(instruction.mnemonic) for instruction in body
        )
        loops.append(
            {
                "instruction_count": len(body),
                "non_zeroing_xor_count": data_xor_count,
                "division_instruction_count": division_count,
                "key_index_modulo_evidence": division_count > 0,
            }
        )
    return loops


def summarize_function(
    image: ELFImage,
    table: GoPCLNTable,
    disassembler: Disassembler,
    function: GoFunction,
    decoder: GoFunction | None,
) -> dict[str, object]:
    """summarize_function produces an allowlisted, content-free report."""

    instructions = disassembler.function(function)
    xor_instructions = [instruction for instruction in instructions if is_xor(instruction.mnemonic)]
    data_xor_count = sum(not is_zeroing_xor(instruction) for instruction in xor_instructions)
    division_count = sum(is_division(instruction.mnemonic) for instruction in instructions)
    xor_loops = find_xor_loops(disassembler, function, instructions)

    backward_branches = 0
    direct_calls: set[str] = set()
    calls_decoder = False
    referenced_sections: set[str] = set()
    immediate_operand_count = 0

    for instruction in instructions:
        if "$" in instruction.operands or re.search(r"(?<![A-Za-z])#-?\d", instruction.operands):
            immediate_operand_count += 1

        if is_branch(instruction.mnemonic):
            target = disassembler.direct_target(instruction)
            if target is not None and function.start <= target < instruction.address:
                backward_branches += 1

        if is_call(instruction.mnemonic):
            target = disassembler.direct_target(instruction)
            if target is not None:
                called = table.by_start(target)
                if called is not None:
                    direct_calls.add(called.name)
                if decoder is not None and target == decoder.start:
                    calls_decoder = True

        referenced = disassembler.referenced_address(instruction)
        if referenced is not None:
            section = image.section_for_address(referenced)
            if section is not None and section.name != ".text":
                referenced_sections.add(section.name)

    code = image.address_bytes(function.start, function.end)
    return {
        "function": function.name,
        "code_size": len(code),
        "code_sha256": hashlib.sha256(code).hexdigest(),
        "instruction_count": len(instructions),
        "xor_instruction_count": len(xor_instructions),
        "non_zeroing_xor_count": data_xor_count,
        "division_instruction_count": division_count,
        "backward_branch_count": backward_branches,
        "xor_loop_count": len(xor_loops),
        "xor_loops_with_modulo_count": sum(
            bool(loop["key_index_modulo_evidence"]) for loop in xor_loops
        ),
        "xor_loops": xor_loops,
        "immediate_operand_count": immediate_operand_count,
        "referenced_non_code_sections": sorted(referenced_sections),
        "direct_calls": sorted(direct_calls),
        "calls_xor_decoder": calls_decoder,
    }


def build_assessment(
    decoder_report: dict[str, object],
    wrapper_reports: Iterable[dict[str, object]],
    analysis_mode: str,
    inline_markers: dict[str, bool],
) -> dict[str, object]:
    """build_assessment converts instruction evidence into bounded conclusions."""

    wrappers = list(wrapper_reports)
    loop_count = int(decoder_report["xor_loop_count"])
    modulo_loop_count = int(decoder_report["xor_loops_with_modulo_count"])
    bytewise_loop = loop_count > 0
    repeating_key_index = modulo_loop_count > 0
    linked_wrappers = [
        str(wrapper["function"])
        for wrapper in wrappers
        if bool(wrapper["calls_xor_decoder"])
    ]
    if analysis_mode == "standalone_decoder":
        credential_path_confirmed = (
            bool(wrappers) and len(linked_wrappers) == len(wrappers)
        )
        embedded_material = credential_path_confirmed and all(
            int(wrapper["immediate_operand_count"]) > 0
            or bool(wrapper["referenced_non_code_sections"])
            for wrapper in wrappers
        )
    else:
        credential_path_confirmed = all(inline_markers.values()) and loop_count >= 2
        embedded_material = credential_path_confirmed and bool(
            decoder_report["referenced_non_code_sections"]
        )

    process_model = (
        "decoded[i] = encoded[i] XOR key[i mod key_length]"
        if bytewise_loop and repeating_key_index
        else "not established"
    )
    return {
        "xor_loop_detected": bytewise_loop,
        "xor_loop_count": loop_count,
        "key_index_modulo_evidence": repeating_key_index,
        "xor_loops_with_modulo_count": modulo_loop_count,
        "process_model": process_model,
        "credential_wrappers_call_decoder": linked_wrappers,
        "credential_path_confirmed": credential_path_confirmed,
        "embedded_material_evidence": embedded_material,
        "conclusion": (
            "The binary contains repeating-key bytewise XOR loops on the "
            "embedded credential path."
            if credential_path_confirmed and bytewise_loop and repeating_key_index
            else "The expected XOR credential structure was not fully confirmed."
        ),
    }


def analyze(binary: Path, objdump: str) -> dict[str, object]:
    """analyze returns a sanitized report for binary."""

    image = ELFImage(binary)
    if image.machine not in {62, 183}:  # EM_X86_64, EM_AARCH64
        raise AnalysisError("only x86-64 and AArch64 ELF binaries are supported")
    table = GoPCLNTable(image)
    disassembler = Disassembler(objdump, binary)

    decoder = table.find_suffix("internal/secret.xorDecode")
    app_key = table.find_suffix("internal/secret.AppKey")
    secret_key = table.find_suffix("internal/secret.SecretKey")
    inline_markers = {
        "internal/secret.AppKey": table.has_name_hint("internal/secret.AppKey"),
        "internal/secret.SecretKey": table.has_name_hint("internal/secret.SecretKey"),
        "internal/secret.xorDecode": table.has_name_hint("internal/secret.xorDecode"),
    }

    if decoder is not None and app_key is not None and secret_key is not None:
        analysis_mode = "standalone_decoder"
        decoder_report = summarize_function(
            image, table, disassembler, decoder, decoder=None
        )
        wrapper_reports = [
            summarize_function(image, table, disassembler, app_key, decoder),
            summarize_function(image, table, disassembler, secret_key, decoder),
        ]
    else:
        container = table.find_suffix("internal/adapter/auth.NewOAuthAdapter")
        if container is None or not all(inline_markers.values()):
            raise AnalysisError("expected bdpan XOR credential path was not found")
        analysis_mode = "inline_decoder"
        decoder_report = summarize_function(
            image, table, disassembler, container, decoder=None
        )
        wrapper_reports = []

    return {
        "schema_version": 1,
        "analysis_mode": analysis_mode,
        "privacy": {
            "content_disclosed": False,
            "decoded_values_emitted": 0,
            "raw_bytes_emitted": 0,
            "disassembly_emitted": False,
            "operands_emitted": False,
        },
        "binary": {
            "size": len(image.data),
            "sha256": hashlib.sha256(image.data).hexdigest(),
            "format": "ELF64 little-endian",
            "architecture": "x86-64" if image.machine == 62 else "AArch64",
            "go_function_count": len(table.functions),
        },
        "decoder": decoder_report,
        "credential_wrappers": wrapper_reports,
        "inline_helper_markers": inline_markers,
        "assessment": build_assessment(
            decoder_report, wrapper_reports, analysis_mode, inline_markers
        ),
    }


def render_text(report: dict[str, object]) -> str:
    """render_text creates a concise, allowlisted human-readable report."""

    binary = report["binary"]
    privacy = report["privacy"]
    decoder = report["decoder"]
    wrappers = report["credential_wrappers"]
    inline_markers = report["inline_helper_markers"]
    assessment = report["assessment"]
    assert isinstance(binary, dict)
    assert isinstance(privacy, dict)
    assert isinstance(decoder, dict)
    assert isinstance(wrappers, list)
    assert isinstance(inline_markers, dict)
    assert isinstance(assessment, dict)

    lines = [
        "bdpan XOR static analysis",
        f"binary_sha256: {binary['sha256']}",
        f"binary_size: {binary['size']}",
        f"architecture: {binary['architecture']}",
        f"go_function_count: {binary['go_function_count']}",
        f"analysis_mode: {report['analysis_mode']}",
        "",
        f"analyzed_function: {decoder['function']}",
        f"  code_size: {decoder['code_size']}",
        f"  code_sha256: {decoder['code_sha256']}",
        f"  instructions: {decoder['instruction_count']}",
        f"  xor_non_zeroing: {decoder['non_zeroing_xor_count']}",
        f"  backward_branches: {decoder['backward_branch_count']}",
        f"  division_or_modulo_evidence: {decoder['division_instruction_count']}",
        f"  xor_loop_candidates: {decoder['xor_loop_count']}",
        f"  xor_loops_with_modulo: {decoder['xor_loops_with_modulo_count']}",
        "",
        "credential wrappers:",
    ]
    if wrappers:
        for wrapper in wrappers:
            assert isinstance(wrapper, dict)
            lines.extend(
                [
                    f"  {wrapper['function']}",
                    f"    code_size: {wrapper['code_size']}",
                    f"    code_sha256: {wrapper['code_sha256']}",
                    f"    calls_xor_decoder: {str(wrapper['calls_xor_decoder']).lower()}",
                    f"    immediate_operand_count: {wrapper['immediate_operand_count']}",
                    "    referenced_non_code_sections: "
                    + ", ".join(wrapper["referenced_non_code_sections"]),
                ]
            )
    else:
        lines.append("  inlined into analyzed_function")
        for name, present in sorted(inline_markers.items()):
            lines.append(f"    {name}: {str(present).lower()}")
    lines.extend(
        [
            "",
            f"xor_loop_detected: {str(assessment['xor_loop_detected']).lower()}",
            f"xor_loop_count: {assessment['xor_loop_count']}",
            "key_index_modulo_evidence: "
            + str(assessment["key_index_modulo_evidence"]).lower(),
            "credential_path_confirmed: "
            + str(assessment["credential_path_confirmed"]).lower(),
            "embedded_material_evidence: "
            + str(assessment["embedded_material_evidence"]).lower(),
            f"process_model: {assessment['process_model']}",
            f"conclusion: {assessment['conclusion']}",
            "",
            "privacy:",
            f"  content_disclosed: {str(privacy['content_disclosed']).lower()}",
            f"  decoded_values_emitted: {privacy['decoded_values_emitted']}",
            f"  raw_bytes_emitted: {privacy['raw_bytes_emitted']}",
            f"  disassembly_emitted: {str(privacy['disassembly_emitted']).lower()}",
            f"  operands_emitted: {str(privacy['operands_emitted']).lower()}",
        ]
    )
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    """parse_args parses command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Analyze bdpan's embedded XOR credential routine without printing "
            "credential content, raw data, disassembly, or instruction operands."
        )
    )
    parser.add_argument("binary", type=Path, help="path to the bdpan ELF binary")
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the same sanitized report as JSON",
    )
    parser.add_argument(
        "--objdump",
        default="objdump",
        help="GNU objdump executable (default: objdump)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """main runs the command-line analyzer."""

    args = parse_args(sys.argv[1:] if argv is None else argv)
    objdump = shutil.which(args.objdump)
    if objdump is None:
        print("error: objdump was not found", file=sys.stderr)
        return 2

    try:
        report = analyze(args.binary, objdump)
    except AnalysisError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
    else:
        print(render_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
