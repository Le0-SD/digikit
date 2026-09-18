import pathlib
import sys
import tempfile
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
import sharc_interface_probe as P  # pyright: ignore[reportMissingImports]


class SharcInterfaceProbeTest(unittest.TestCase):
    def test_extract_machine_types(self):
        frame = bytearray(0x802)
        expected = [0, 1, 6, 0x1234] + list(range(4, 16))
        for track, value in enumerate(expected):
            start = P.MACHINE_OFFSET + 2 * track
            frame[start : start + 2] = value.to_bytes(2, "big")
        self.assertEqual(P.extract_machine_types(bytes(frame)), expected)

    def test_extract_machine_types_rejects_short_frame(self):
        for size in (P.TX_FRAME_BYTES - 1, P.TX_FRAME_BYTES + 1):
            with self.subTest(size=size), self.assertRaisesRegex(
                ValueError, "expected exactly 2050"
            ):
                P.extract_machine_types(bytes(size))

    def test_build_report_rejects_wrong_image_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            blob = pathlib.Path(directory) / "section_7_BLOB.bin"
            blob.write_bytes(b"not the qualifying image")
            with self.assertRaisesRegex(ValueError, "wrong SHARC image"):
                P.build_report(blob)


if __name__ == "__main__":
    unittest.main()
