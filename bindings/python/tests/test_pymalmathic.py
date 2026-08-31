import hashlib
import os
import struct
import unittest

import pymalmathic as mm

try:
    import pefile
    import ordlookup
except ImportError:
    pefile = None
    ordlookup = None

SECTION_VA = 0x1000
FILE_ALIGN = 0x200
HEADERS = 0x400
LFANEW = 0x80
DANS = 0x536E6144
FROZEN_TABLES = ordlookup is not None and hasattr(ordlookup, "imphash_ords")


def pe_with_imports(spec, pe64=True, header_region=False):
    blob = bytearray(b"\0" * (20 * (len(spec) + 1)))
    base = 0x200 if header_region else SECTION_VA
    entry_size = 8 if pe64 else 4
    ordflag = 1 << 63 if pe64 else 1 << 31
    for i, d in enumerate(spec):
        thunks = []
        for kind, v in d.get("funcs", []):
            if kind == "name":
                at = len(blob)
                blob += b"\0\0" + v + b"\0"
                if len(blob) % 2:
                    blob += b"\0"
                thunks.append(base + at)
            elif kind == "ord":
                thunks.append(ordflag | v)
            else:
                thunks.append(v)
        dll = d.get("dll", b"KERNEL32.dll")
        if isinstance(dll, bytes):
            dll_rva = base + len(blob)
            blob += dll + b"\0"
        else:
            dll_rva = dll
        table_rva = base + len(blob)
        for t in thunks:
            blob += struct.pack("<Q", t) if pe64 else struct.pack("<I", t & 0xFFFFFFFF)
        blob += b"\0" * entry_size
        mode = d.get("oft", "both")
        oft, ft = {
            "both": (table_rva, table_rva),
            "garbage": (0x7FFF0000, table_rva),
            "zero": (0, table_rva),
            "only": (table_rva, 0),
        }[mode]
        struct.pack_into("<IIIII", blob, 20 * i, oft, 0, 0, dll_rva, ft)

    image = bytearray(HEADERS)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, LFANEW)
    image[LFANEW:LFANEW + 4] = b"PE\0\0"
    coff = LFANEW + 4
    opt_size = 240 if pe64 else 224
    struct.pack_into("<HHIIIHH", image, coff, 0x8664 if pe64 else 0x14C, 1, 0, 0, 0, opt_size, 0x22)
    opt = coff + 20
    struct.pack_into("<H", image, opt, 0x20B if pe64 else 0x10B)
    struct.pack_into("<I", image, opt + 16, SECTION_VA)
    struct.pack_into("<I", image, opt + 32, 0x1000)
    struct.pack_into("<I", image, opt + 36, FILE_ALIGN)
    struct.pack_into("<H", image, opt + 40, 6)
    struct.pack_into("<H", image, opt + 48, 6)
    struct.pack_into("<I", image, opt + 56, SECTION_VA * 4)
    struct.pack_into("<I", image, opt + 60, HEADERS)
    struct.pack_into("<H", image, opt + 68, 2)
    if pe64:
        struct.pack_into("<Q", image, opt + 24, 0x140000000)
        struct.pack_into("<I", image, opt + 108, 16)
        dirs = opt + 112
    else:
        struct.pack_into("<I", image, opt + 28, 0x400000)
        struct.pack_into("<I", image, opt + 92, 16)
        dirs = opt + 96
    struct.pack_into("<II", image, dirs + 8, base, 20 * (len(spec) + 1))
    if header_region:
        image[0x200:0x200 + len(blob)] = blob
        section = bytearray(b"\xCC" * 64)
    else:
        section = bytearray(blob)
    raw_size = (len(section) + FILE_ALIGN - 1) // FILE_ALIGN * FILE_ALIGN
    section += b"\0" * (raw_size - len(section))
    sect = opt + opt_size
    image[sect:sect + 8] = b".rdata\0\0"
    struct.pack_into("<IIIIIIHHI", image, sect + 8, len(section), SECTION_VA, raw_size, HEADERS, 0, 0, 0, 0, 0x40000040)
    return bytes(image + section)


def rol32(value, count):
    count &= 31
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def rich_checksum(stub, entries):
    total = 0x80
    for i, b in enumerate(stub[:0x80]):
        if 0x3C <= i < 0x40:
            continue
        total = (total + rol32(b, i)) & 0xFFFFFFFF
    for product_id, build, count in entries:
        total = (total + rol32((product_id << 16) | build, count)) & 0xFFFFFFFF
    return total


def pe_with_rich(entries, stored_key=lambda k: k, xor_key=lambda k: k):
    clear = struct.pack("<I", DANS) + b"\0" * 12
    for product_id, build, count in entries:
        clear += struct.pack("<II", (product_id << 16) | build, count)
    image = bytearray(0x80)
    image[0:2] = b"MZ"
    for i in range(0x40, 0x80):
        image[i] = i % 251
    key = rich_checksum(image, entries)
    stored = stored_key(key)
    xor = struct.pack("<I", xor_key(key))
    image += bytes(b ^ xor[i % 4] for i, b in enumerate(clear))
    image += b"Rich" + struct.pack("<I", stored)
    while len(image) % 8:
        image += b"\0"
    struct.pack_into("<I", image, 0x3C, len(image))
    image += b"PE\0\0" + b"\0" * (20 + 240)
    return bytes(image)


def md5(text):
    return hashlib.md5(text.encode()).hexdigest()


class HostileInput(unittest.TestCase):
    SAMPLES = [b"", b"M", b"MZ", b"\0" * 4096, b"\xff" * 4096, b"the quick brown fox\n" * 64]

    def test_every_parser_survives_garbage(self):
        for sample in self.SAMPLES:
            self.assertIsInstance(mm.parse_amcache(sample), list)
            self.assertIsInstance(mm.parse_shimcache(sample), list)
            self.assertIsInstance(mm.parse_prefetch(sample, "X.EXE-00000000.pf"), list)
            self.assertIsInstance(mm.parse_tasks(sample, "\\Vendor\\Task"), list)
            self.assertIsInstance(mm.parse_defender_log(sample), list)
            self.assertIsInstance(mm.parse_persistence(sample, "software"), list)
            self.assertIsInstance(mm.parse_recycle_bin("$IABCDEF.exe", sample), list)
            self.assertIsInstance(mm.analyze_pe(sample, "C:\\x.exe"), list)
            self.assertIsNone(mm.imphash(sample))
            self.assertIsNone(mm.imports(sample))
            self.assertIsNone(mm.rich_header(sample))

    def test_truncated_pe_yields_nothing(self):
        good = pe_with_imports([{"funcs": [("name", b"ExitProcess")]}])
        for cut in (0x90, 0x200, len(good) - 8):
            mm.imphash(good[:cut])
            mm.imports(good[:cut])
            mm.rich_header(good[:cut])


class Arguments(unittest.TestCase):
    def test_hive_source_is_validated(self):
        for bad in ("bogus", "ntuser", "ntuser:", "usrclass:"):
            with self.assertRaises(ValueError):
                mm.parse_persistence(b"", bad)
        for good in ("software", "SYSTEM", "ntuser:bob", "usrclass:bob"):
            self.assertEqual(mm.parse_persistence(b"", good), [])

    def test_a_path_that_is_not_a_windows_path_is_refused(self):
        with self.assertRaises(ValueError):
            mm.analyze_pe(b"MZ", "")

    def test_a_missing_image_raises_oserror(self):
        with self.assertRaises(OSError):
            mm.Image(os.path.join(os.path.dirname(__file__), "no-such-image.vmdk"))


class Imphash(unittest.TestCase):
    def test_plain_imports_hash_the_joined_lowercase_strings(self):
        image = pe_with_imports([
            {"dll": b"KERNEL32.dll", "funcs": [("name", b"CreateFileW"), ("name", b"ExitProcess")]},
            {"dll": b"USER32.DLL", "funcs": [("name", b"MessageBoxA")]},
        ])
        self.assertEqual(mm.imports(image), ["kernel32.createfilew", "kernel32.exitprocess", "user32.messageboxa"])
        self.assertEqual(mm.imphash(image), md5("kernel32.createfilew,kernel32.exitprocess,user32.messageboxa"))

    def test_pe32_reads_the_same(self):
        image = pe_with_imports([{"funcs": [("name", b"ExitProcess")]}], pe64=False)
        self.assertEqual(mm.imports(image), ["kernel32.exitprocess"])

    def test_frozen_ordinal_tables(self):
        image = pe_with_imports([{"dll": b"WS2_32.dll", "funcs": [("ord", 3), ("ord", 24), ("ord", 9999)]}])
        self.assertEqual(mm.imports(image), ["ws2_32.closesocket", "ws2_32.getaddrinfow", "ws2_32.ord9999"])
        image = pe_with_imports([{"dll": b"OLEAUT32.dll", "funcs": [("ord", 144), ("ord", 2)]}])
        self.assertEqual(mm.imports(image), ["oleaut32.dllcanunloadnow", "oleaut32.sysallocstring"])

    def test_pefile_rules_on_odd_tables(self):
        self.assertIsNone(mm.imphash(pe_with_imports([])))
        self.assertEqual(mm.imports(pe_with_imports([{"funcs": [("name", b"Create-File"), ("name", b"ExitProcess")]}])), ["kernel32.exitprocess"])
        self.assertEqual(mm.imports(pe_with_imports([{"dll": b"my lib.dll", "funcs": [("name", b"Fn")]}])), ["*invalid*.fn"])
        self.assertEqual(mm.imports(pe_with_imports([{"funcs": [("ord", 0), ("name", b"ExitProcess")]}])), ["kernel32.exitprocess"])
        self.assertEqual(mm.imports(pe_with_imports([{"oft": "garbage", "funcs": [("name", b"ExitProcess")]}])), ["kernel32.exitprocess"])
        self.assertEqual(mm.imports(pe_with_imports([{"funcs": [("name", b"ExitProcess")]}], header_region=True)), ["kernel32.exitprocess"])
        six = [{"dll": b"e%d.dll" % i, "funcs": []} for i in range(6)] + [{"dll": b"USER32.dll", "funcs": [("name", b"MessageBoxA")]}]
        self.assertIsNone(mm.imphash(pe_with_imports(six)))

    @unittest.skipIf(pefile is None, "pefile is not installed")
    def test_synthetic_tables_agree_with_pefile(self):
        cases = [
            [{"funcs": [("name", b"CreateFileW"), ("name", b"ExitProcess")]}],
            [{"funcs": [("name", b"Create-File"), ("name", b"?foo@@YAXXZ"), ("name", b"$bar")]}],
            [{"dll": b"my lib.dll", "funcs": [("name", b"Fn")]}],
            [{"dll": b"lib\xe9.dll", "funcs": [("name", b"Fn")]}],
            [{"dll": b"sub\\lib.dll", "funcs": [("name", b"Fn")]}],
            [{"dll": 0x7FFF0000, "funcs": [("name", b"Fn")]}, {"dll": b"USER32.dll", "funcs": [("name", b"MessageBoxA")]}],
            [{"funcs": [("name", b"First"), ("raw", 0x7FFF0000), ("name", b"Third")]}],
            [{"dll": b"e%d.dll" % i, "funcs": []} for i in range(5)] + [{"dll": b"USER32.dll", "funcs": [("name", b"MessageBoxA")]}],
            [{"dll": b"e%d.dll" % i, "funcs": []} for i in range(6)] + [{"dll": b"USER32.dll", "funcs": [("name", b"MessageBoxA")]}],
            [{"oft": "garbage", "funcs": [("name", b"ExitProcess")]}],
            [{"oft": "zero", "funcs": [("name", b"ExitProcess")]}],
            [{"oft": "only", "funcs": [("name", b"ExitProcess")]}],
            [{"funcs": [("ord", 0), ("name", b"ExitProcess")]}],
            [{"funcs": [("ord", 7), ("name", b"ExitProcess")]}],
            [{"funcs": [("raw", (1 << 63) | 0x12340007), ("name", b"ExitProcess")]}],
            [{"funcs": [("raw", (1 << 40) | (SECTION_VA + 0x30)), ("name", b"ExitProcess")]}],
            [{"funcs": [("name", b"Same")] + [("raw", SECTION_VA + 40)] * 16}],
            [{"funcs": [("name", b""), ("name", b"ExitProcess")]}],
            [{"dll": b"HELPER.exe", "funcs": [("name", b"Fn")]}],
            [{"dll": b"two.parts.dll", "funcs": [("name", b"Fn")]}],
            [],
            [{"dll": b"big%d.dll" % i, "funcs": [("name", b"F%05d" % (i * 100 + j)) for j in range(100)]} for i in range(60)],
        ]
        layouts = [{}, {"pe64": False}, {"header_region": True}]
        for spec in cases:
            for layout in layouts:
                image = pe_with_imports(spec, **layout)
                try:
                    expected = pefile.PE(data=image).get_imphash()
                except pefile.PEFormatError:
                    continue
                got = mm.imphash(image) or ""
                self.assertEqual(got, expected, f"{spec[:2]} {layout}")

    @unittest.skipIf(pefile is None or not os.path.isdir(r"C:\Windows\System32"), "needs pefile and a Windows system directory")
    def test_system32_agrees_with_pefile(self):
        root = r"C:\Windows\System32"
        names = sorted(n for n in os.listdir(root) if n.lower().endswith((".exe", ".dll", ".sys")))[:300]
        compared = 0
        for name in names:
            try:
                with open(os.path.join(root, name), "rb") as handle:
                    data = handle.read()
                pe = pefile.PE(data=data, fast_load=True)
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
                rich = pe.parse_rich_header()
            except Exception:
                continue
            tabled = (b"ws2_32.dll", b"wsock32.dll", b"oleaut32.dll")
            by_ordinal = any(
                imp.import_by_ordinal
                for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
                if entry.dll.lower() in tabled
                for imp in entry.imports
            )
            if by_ordinal and not FROZEN_TABLES:
                continue
            self.assertEqual(mm.imphash(data) or "", pe.get_imphash(), name)
            expected_rich = hashlib.md5(rich["clear_data"]).hexdigest() if rich else ""
            got = mm.rich_header(data)
            self.assertEqual(got["hash"] if got else "", expected_rich, name)
            compared += 1
        self.assertGreater(compared, 50)


class RichHeader(unittest.TestCase):
    def test_a_genuine_header_verifies(self):
        rich = mm.rich_header(pe_with_rich([(0x0102, 27412, 9), (0x00FF, 30729, 3)]))
        self.assertTrue(rich["checksum_valid"])
        self.assertTrue(rich["dans_decoded"])
        self.assertEqual(rich["entries"], [
            {"product_id": 0x0102, "build": 27412, "count": 9},
            {"product_id": 0x00FF, "build": 30729, "count": 3},
        ])
        self.assertEqual(len(rich["hash"]), 32)

    def test_a_mismatched_key_and_an_undecodable_block_are_both_invalid(self):
        forged = mm.rich_header(pe_with_rich([(0x0102, 27412, 9)], stored_key=lambda k: k ^ 0x0F0F0F0F, xor_key=lambda k: k ^ 0x0F0F0F0F))
        self.assertFalse(forged["checksum_valid"])
        self.assertTrue(forged["dans_decoded"])
        planted = mm.rich_header(pe_with_rich([(0x0102, 27412, 9)], stored_key=lambda k: k ^ 0x0F0F0F0F))
        self.assertFalse(planted["checksum_valid"])
        self.assertFalse(planted["dans_decoded"])
        self.assertEqual(len(planted["hash"]), 32)

    def test_analyze_pe_reports_the_forgery(self):
        forged = pe_with_rich([(0x0102, 27412, 9)], stored_key=lambda k: k ^ 0x0F0F0F0F, xor_key=lambda k: k ^ 0x0F0F0F0F)
        kinds = [o["kind"] for o in mm.analyze_pe(forged, "C:\\Users\\bob\\x.exe")]
        self.assertTrue(any("RichHeaderChecksumInvalid" in str(k) for k in kinds), kinds)
        genuine = pe_with_rich([(0x0102, 27412, 9)])
        kinds = [o["kind"] for o in mm.analyze_pe(genuine, "C:\\Users\\bob\\x.exe")]
        self.assertFalse(any("RichHeaderChecksumInvalid" in str(k) for k in kinds), kinds)


@unittest.skipUnless(os.environ.get("MM_TEST_IMAGE"), "set MM_TEST_IMAGE to a disk image to exercise Image")
class DiskImage(unittest.TestCase):
    def test_the_image_opens_and_lists(self):
        image = mm.Image(os.environ["MM_TEST_IMAGE"])
        self.assertIn(image.offset, image.partitions)
        self.assertEqual(len(image.serial()), 16)
        self.assertIsInstance(image.list_dir("\\"), list)
        if image.is_windows():
            self.assertTrue(image.exists("\\Windows\\System32"))
            hive = image.read_file("\\Windows\\System32\\config\\SOFTWARE", max_bytes=1 << 20)
            self.assertLessEqual(len(hive), 1 << 20)


if __name__ == "__main__":
    unittest.main()
