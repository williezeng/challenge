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
        self.test_data_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), 'test_data')
        )

    def test_reading_test_data(self):
        payload_instance = Payload(self.test_data_dir)
        self.assertEqual(len(payload_instance.file_paths), 2)
        self.assertIsNotNone(payload_instance.data_a)
        self.assertIsNotNone(payload_instance.data_b)



if __name__ == '__main__':
    unittest.main()
