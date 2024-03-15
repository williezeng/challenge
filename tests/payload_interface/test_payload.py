import unittest
import tempfile
import shutil
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from payload_exceptions import PcapFileError
from payload_interface import Payload


class TestPayload(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def create_test_files(self, dir_name, num_files):
        dir_path = os.path.join(self.test_dir, dir_name)
        os.makedirs(dir_path, exist_ok=True)
        for i in range(num_files):
            with open(os.path.join(dir_path, f"file{i}.pcap"), 'w') as f:
                f.write("dummy data")
        return dir_path

    def test_non_existent_directory(self):
        with self.assertRaises(AssertionError):
            Payload("/path/to/nonexistent/directory")

    def test_no_files_found(self):
        dir_path = self.create_test_files("empty_dir", 0)
        with self.assertRaises(AssertionError):
            Payload(dir_path)

    def test_more_than_two_files_raises_assertion_error(self):
        dir_path = self.create_test_files("more_than_two", 3)
        with self.assertRaises(PcapFileError):
            Payload(dir_path)


class TestPayloadDataReading(unittest.TestCase):

    def setUp(self):
        self.test_file_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), 'test_data',
                         '1567029600000000000_xcme_delta-s1p1-udp_0.0.0.0_0-224.0.31.1_14310-00000000.pcap.xz')
        )

    def test_reading_test_data(self):
        payload_instance = Payload(self.test_file_path)
        time_information = payload_instance.get_time_information()
        import pdb
        pdb.set_trace()
    def test_payload_extraction(self):
        udp_payload = b'\xbbI\xb6\x01\x98k\x01\xfd\xdcs\xbf\x15X\x00\x0b\x00.\x00\x01\x00\t\x00\x97\xc6\xff\xfc\xdcs\xbf\x15\x84\x00\x00 \x00\x01\x00$K\xe3)\n\x01\x00l\x00\x00\x00C\x93\x00\x00\x87\xc0\x91\x01$\x00\x00\x00\x01\x011\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x01D\xdd\x88e\x96\x00\x00\x00\xbb7\x81\xbf\x01\x00\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00\xc4\x8b\xae\xf4\x00\xdf\x1e ]h\x06\xdc\x13@\x18\x88\x03\x00(\x11'
        sequence_number = b'\xbbI\xb6\x01'
        sending_time = b'\x98k\x01\xfd\xdcs\xbf\x15'
        seconds_since_epoch = b']h\x06\xdc'
        nanoseconds_correction = b'\x13@\x18\x88'

        Payload.get_time_information(udp_payload)
if __name__ == '__main__':
    unittest.main()
