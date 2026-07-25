#!/usr/bin/env python3
"""Integration tests for the privacy-safe bdpan XOR analyzer."""

from __future__ import annotations

import json
import logging
import os
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ANALYZER = Path(__file__).with_name("analyze_bdpan_xor.py")
TEXT_ADDRESS = 0x401000
PCLN_ADDRESS = 0x402000
REAL_BDPAN_SHA256 = "f4d80c4cc97ddd3bcc230f2c82ab96d9be32cbe8e27f7fcc91cb23bb27b62d58"
SYNTHETIC_CONTENT = (
    "SYNTHETIC_APP_CLIENT_CONTENT_DO_NOT_REPORT",
    "SYNTHETIC_SECRET_CONTENT_DO_NOT_REPORT",
    "SYNTHETIC_XOR_KEY_CONTENT_DO_NOT_REPORT",
)
LOGGER = logging.getLogger("bdpan_xor_test")


def configure_debug_logging() -> None:
    """configure_debug_logging enables safe test diagnostics on the console."""

    logging.basicConfig(
        level=logging.DEBUG,
        format="DEBUG %(name)s: %(message)s",
        stream=sys.stderr,
        force=True,
    )


def align(value: int, alignment: int) -> int:
    """align rounds value up to alignment."""

    return (value + alignment - 1) // alignment * alignment


def make_pclntab(
    functions: list[tuple[str, int, int]],
    extra_names: tuple[str, ...] = (),
) -> bytes:
    """make_pclntab builds the Go 1.20 metadata subset used by the analyzer."""

    names: list[str] = []
    for name, _, _ in functions:
        if name not in names:
            names.append(name)
    for name in extra_names:
        if name not in names:
            names.append(name)

    names_blob = bytearray()
    name_offsets: dict[str, int] = {}
    for name in names:
        name_offsets[name] = len(names_blob)
        names_blob.extend(name.encode("utf-8"))
        names_blob.append(0)

    names_offset = 0x80
    function_data_offset = align(names_offset + len(names_blob), 0x40)
    table_size = len(functions) * 8 + 4
    metadata_offset = align(function_data_offset + table_size, 8)
    total_size = metadata_offset + len(functions) * 8
    data = bytearray(total_size)

    struct.pack_into("<I", data, 0, 0xFFFFFFF1)
    data[4:8] = b"\x00\x00\x01\x08"
    words = (
        len(functions),
        0,
        TEXT_ADDRESS,
        names_offset,
        0,
        0,
        0,
        function_data_offset,
    )
    for index, word in enumerate(words):
        struct.pack_into("<Q", data, 8 + index * 8, word)
    data[names_offset : names_offset + len(names_blob)] = names_blob

    for index, (name, start, _) in enumerate(functions):
        function_metadata = metadata_offset + index * 8
        struct.pack_into(
            "<II",
            data,
            function_data_offset + index * 8,
            start,
            function_metadata - function_data_offset,
        )
        struct.pack_into("<Ii", data, function_metadata, 0, name_offsets[name])

    struct.pack_into(
        "<I",
        data,
        function_data_offset + len(functions) * 8,
        functions[-1][2],
    )
    return bytes(data)


def make_elf(
    path: Path,
    functions: list[tuple[str, int, int]],
    extra_names: tuple[str, ...] = (),
) -> None:
    """make_elf writes a minimal x86-64 ELF carrying a Go PC/line table."""

    text_size = max(end for _, _, end in functions)
    text = bytes((index * 17 + 3) & 0xFF for index in range(text_size))
    pclntab = make_pclntab(functions, extra_names)
    section_names = b"\x00.text\x00.gopclntab\x00.shstrtab\x00"
    text_name = section_names.index(b".text")
    pcln_name = section_names.index(b".gopclntab")
    shstr_name = section_names.index(b".shstrtab")

    text_offset = 0x100
    pcln_offset = align(text_offset + len(text), 0x100)
    shstr_offset = pcln_offset + len(pclntab)
    section_table_offset = align(shstr_offset + len(section_names), 8)
    section_count = 4
    total_size = section_table_offset + section_count * 64
    image = bytearray(total_size)

    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4] = 2
    ident[5] = 1
    ident[6] = 1
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        image,
        0,
        bytes(ident),
        2,
        62,
        1,
        TEXT_ADDRESS,
        0,
        section_table_offset,
        0,
        64,
        0,
        0,
        64,
        section_count,
        3,
    )
    image[text_offset : text_offset + len(text)] = text
    image[pcln_offset : pcln_offset + len(pclntab)] = pclntab
    image[shstr_offset : shstr_offset + len(section_names)] = section_names

    section_struct = struct.Struct("<IIQQQQIIQQ")
    section_struct.pack_into(
        image,
        section_table_offset + 64,
        text_name,
        1,
        0x6,
        TEXT_ADDRESS,
        text_offset,
        len(text),
        0,
        0,
        16,
        0,
    )
    section_struct.pack_into(
        image,
        section_table_offset + 128,
        pcln_name,
        1,
        0x2,
        PCLN_ADDRESS,
        pcln_offset,
        len(pclntab),
        0,
        0,
        8,
        0,
    )
    section_struct.pack_into(
        image,
        section_table_offset + 192,
        shstr_name,
        3,
        0,
        0,
        shstr_offset,
        len(section_names),
        0,
        0,
        1,
        0,
    )
    path.write_bytes(image)


def make_fake_objdump(path: Path, disassembly: dict[int, str]) -> None:
    """make_fake_objdump writes a deterministic objdump-compatible fixture."""

    source = f"""#!/usr/bin/env python3
import sys

outputs = {disassembly!r}
argument = next(value for value in sys.argv if value.startswith("--start-address="))
start = int(argument.split("=", 1)[1], 0)
print(outputs.get(start, ""))
"""
    path.write_text(source, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class AnalyzerIntegrationTest(unittest.TestCase):
    """AnalyzerIntegrationTest exercises both compiler layouts end to end."""

    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        configure_debug_logging()
        LOGGER.debug("starting privacy-safe bdpan XOR analyzer tests")

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.directory = Path(self.temporary_directory.name)

    def run_analyzer(
        self,
        binary: Path,
        objdump: Path | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object] | None]:
        """run_analyzer invokes the CLI and decodes a successful JSON report."""

        command = [sys.executable, "-B", os.fspath(ANALYZER), "--json"]
        if objdump is not None:
            command.extend(["--objdump", os.fspath(objdump)])
        command.append(os.fspath(binary))
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        report = json.loads(result.stdout) if result.returncode == 0 else None
        LOGGER.debug(
            "analyzer target=%s format=json objdump=%s exit_code=%d",
            binary,
            objdump if objdump is not None else "system-default",
            result.returncode,
        )
        if report is not None:
            assessment = report["assessment"]
            privacy = report["privacy"]
            assert isinstance(assessment, dict)
            assert isinstance(privacy, dict)
            LOGGER.debug(
                "analysis mode=%s xor_loops=%s modulo_loops=%s "
                "credential_path_confirmed=%s",
                report["analysis_mode"],
                assessment["xor_loop_count"],
                assessment["xor_loops_with_modulo_count"],
                assessment["credential_path_confirmed"],
            )
            LOGGER.debug(
                "privacy content_disclosed=%s raw_bytes=%s decoded_values=%s "
                "disassembly=%s operands=%s",
                privacy["content_disclosed"],
                privacy["raw_bytes_emitted"],
                privacy["decoded_values_emitted"],
                privacy["disassembly_emitted"],
                privacy["operands_emitted"],
            )
        return result, report

    def run_text_analyzer(
        self,
        binary: Path,
        objdump: Path,
    ) -> subprocess.CompletedProcess[str]:
        """run_text_analyzer invokes the human-readable reporter."""

        result = subprocess.run(
            [
                sys.executable,
                "-B",
                os.fspath(ANALYZER),
                "--objdump",
                os.fspath(objdump),
                os.fspath(binary),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        LOGGER.debug(
            "analyzer target=%s format=text objdump=%s exit_code=%d",
            binary,
            objdump,
            result.returncode,
        )
        return result

    def assert_private_report(
        self,
        result: subprocess.CompletedProcess[str],
        report: dict[str, object],
    ) -> None:
        """assert_private_report verifies the reporter's disclosure boundary."""

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            report["privacy"],
            {
                "content_disclosed": False,
                "decoded_values_emitted": 0,
                "disassembly_emitted": False,
                "operands_emitted": False,
                "raw_bytes_emitted": 0,
            },
        )
        emitted = result.stdout + result.stderr
        for content in SYNTHETIC_CONTENT:
            self.assertNotIn(content, emitted)

    def test_inline_decoder_detects_two_modulo_xor_loops(self) -> None:
        """The inline layout detects two loops and deduplicates an outer loop."""

        adapter_name = "example.test/bdpan/internal/adapter/auth.NewOAuthAdapter"
        functions = [(adapter_name, 0x000, 0x100)]
        inline_names = (
            "example.test/bdpan/internal/secret.AppKey",
            "example.test/bdpan/internal/secret.SecretKey",
            "example.test/bdpan/internal/secret.xorDecode",
            *SYNTHETIC_CONTENT,
        )
        binary = self.directory / "inline-bdpan"
        make_elf(binary, functions, inline_names)

        objdump = self.directory / "objdump-inline"
        make_fake_objdump(
            objdump,
            {
                TEXT_ADDRESS: """
  401000: idiv   %rcx
  401004: xor    %r8b,%r9b
  401008: jl     401000
  40100c: idiv   %rcx
  401010: xor    %r10b,%r11b
  401014: jl     40100c
  401018: jl     401000
  40101c: lea    0x0(%rip),%rax # 402000
  401020: ret
""",
            },
        )

        result, report = self.run_analyzer(binary, objdump)
        self.assertIsNotNone(report, result.stderr)
        assert report is not None
        self.assert_private_report(result, report)
        self.assertEqual(report["analysis_mode"], "inline_decoder")
        assessment = report["assessment"]
        self.assertIsInstance(assessment, dict)
        assert isinstance(assessment, dict)
        self.assertEqual(assessment["xor_loop_count"], 2)
        self.assertEqual(assessment["xor_loops_with_modulo_count"], 2)
        self.assertTrue(assessment["credential_path_confirmed"])
        self.assertTrue(assessment["embedded_material_evidence"])
        self.assertEqual(
            assessment["process_model"],
            "decoded[i] = encoded[i] XOR key[i mod key_length]",
        )

        text_result = self.run_text_analyzer(binary, objdump)
        self.assertEqual(text_result.returncode, 0, text_result.stderr)
        self.assertIn(
            "process_model: decoded[i] = encoded[i] XOR key[i mod key_length]",
            text_result.stdout,
        )
        emitted = text_result.stdout + text_result.stderr
        for content in SYNTHETIC_CONTENT:
            self.assertNotIn(content, emitted)

    def test_zeroing_xor_is_not_classified_as_a_decoder(self) -> None:
        """Register-zeroing XOR instructions are a negative control."""

        adapter_name = "example.test/bdpan/internal/adapter/auth.NewOAuthAdapter"
        functions = [(adapter_name, 0x000, 0x100)]
        inline_names = (
            "example.test/bdpan/internal/secret.AppKey",
            "example.test/bdpan/internal/secret.SecretKey",
            "example.test/bdpan/internal/secret.xorDecode",
            *SYNTHETIC_CONTENT,
        )
        binary = self.directory / "zeroing-xor-bdpan"
        make_elf(binary, functions, inline_names)

        objdump = self.directory / "objdump-zeroing-xor"
        make_fake_objdump(
            objdump,
            {
                TEXT_ADDRESS: """
  401000: idiv   %rcx
  401004: xor    %eax,%eax
  401008: jl     401000
  40100c: idiv   %rcx
  401010: xor    %r8d,%r8d
  401014: jl     40100c
  401018: lea    0x0(%rip),%rax # 402000
  40101c: ret
""",
            },
        )

        result, report = self.run_analyzer(binary, objdump)
        self.assertIsNotNone(report, result.stderr)
        assert report is not None
        self.assert_private_report(result, report)
        assessment = report["assessment"]
        self.assertIsInstance(assessment, dict)
        assert isinstance(assessment, dict)
        self.assertEqual(assessment["xor_loop_count"], 0)
        self.assertEqual(assessment["xor_loops_with_modulo_count"], 0)
        self.assertFalse(assessment["credential_path_confirmed"])
        self.assertEqual(assessment["process_model"], "not established")

    def test_standalone_decoder_links_both_wrappers(self) -> None:
        """The standalone layout links both accessors to one XOR decoder."""

        decoder_name = "example.test/bdpan/internal/secret.xorDecode"
        app_key_name = "example.test/bdpan/internal/secret.AppKey"
        secret_key_name = "example.test/bdpan/internal/secret.SecretKey"
        functions = [
            (decoder_name, 0x000, 0x100),
            (app_key_name, 0x100, 0x180),
            (secret_key_name, 0x180, 0x200),
        ]
        binary = self.directory / "standalone-bdpan"
        make_elf(binary, functions, SYNTHETIC_CONTENT)

        objdump = self.directory / "objdump-standalone"
        make_fake_objdump(
            objdump,
            {
                TEXT_ADDRESS: """
  401000: idiv   %rcx
  401004: xor    %r8b,%r9b
  401008: jl     401000
  40100c: ret
""",
                TEXT_ADDRESS + 0x100: """
  401100: lea    0x0(%rip),%rax # 402000
  401104: call   401000
  401108: ret
""",
                TEXT_ADDRESS + 0x180: """
  401180: lea    0x0(%rip),%rax # 402000
  401184: call   401000
  401188: ret
""",
            },
        )

        result, report = self.run_analyzer(binary, objdump)
        self.assertIsNotNone(report, result.stderr)
        assert report is not None
        self.assert_private_report(result, report)
        self.assertEqual(report["analysis_mode"], "standalone_decoder")
        assessment = report["assessment"]
        self.assertIsInstance(assessment, dict)
        assert isinstance(assessment, dict)
        self.assertEqual(assessment["xor_loop_count"], 1)
        self.assertEqual(assessment["xor_loops_with_modulo_count"], 1)
        self.assertEqual(
            assessment["credential_wrappers_call_decoder"],
            [app_key_name, secret_key_name],
        )
        self.assertTrue(assessment["credential_path_confirmed"])
        self.assertTrue(assessment["embedded_material_evidence"])

    def test_invalid_input_is_rejected_without_echoing_content(self) -> None:
        """Invalid input returns a safe error without reflecting its bytes."""

        binary = self.directory / "not-an-elf"
        binary.write_text(SYNTHETIC_CONTENT[1], encoding="utf-8")
        result, report = self.run_analyzer(binary)
        self.assertIsNone(report)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(SYNTHETIC_CONTENT[1], result.stderr)
        self.assertIn("input is too small to be an ELF binary", result.stderr)

    @unittest.skipUnless(
        os.environ.get("BDPAN_3_8_4_BINARY"),
        "set BDPAN_3_8_4_BINARY to run the real-binary regression",
    )
    def test_real_bdpan_3_8_4_regression(self) -> None:
        """The downloaded 3.8.4 binary retains the expected private structure."""

        binary = Path(os.environ["BDPAN_3_8_4_BINARY"])
        result, report = self.run_analyzer(binary)
        self.assertIsNotNone(report, result.stderr)
        assert report is not None
        self.assert_private_report(result, report)
        self.assertEqual(report["binary"]["sha256"], REAL_BDPAN_SHA256)
        self.assertEqual(report["analysis_mode"], "inline_decoder")
        assessment = report["assessment"]
        self.assertIsInstance(assessment, dict)
        assert isinstance(assessment, dict)
        self.assertEqual(assessment["xor_loop_count"], 2)
        self.assertEqual(assessment["xor_loops_with_modulo_count"], 2)
        self.assertTrue(assessment["credential_path_confirmed"])


if __name__ == "__main__":
    unittest.main()
