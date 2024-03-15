import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from payload_exceptions import PcapFileError, IncompleteUDPPayload, DirError
from payload_interface import Payload
import payload_comparer
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class TestPayloadDataReading(unittest.TestCase):
    def setUp(self):
        self.test_file_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), 'test_data',
                         'test1.pcap.xz')
        )

    def test_unsupported_file_format(self):
        with self.assertRaises(PcapFileError):
            Payload("/path/to/nonexistent/file")

    def test_reading_test_data(self):
        payload_instance = Payload(self.test_file_path)
        dict_of_times = payload_instance.get_time_information
        # sequence number, [sending_time, seconds_since_epoch, nanoseconds_correction]
        self.assertEqual(dict_of_times[28746229], [1567098852483666925, 3825690717, 3060847644])
        self.assertEqual(dict_of_times[28746269], [1567098852792685381, 3825690717, 1705983791])


    def test_successful_payload_extraction(self):
        udp_payload = b'\xbbI\xb6\x01\x98k\x01\xfd\xdcs\xbf\x15X\x00\x0b\x00.\x00\x01\x00\t\x00\x97\xc6\xff\xfc\xdcs\xbf\x15\x84\x00\x00 \x00\x01\x00$K\xe3)\n\x01\x00l\x00\x00\x00C\x93\x00\x00\x87\xc0\x91\x01$\x00\x00\x00\x01\x011\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x01D\xdd\x88e\x96\x00\x00\x00\xbb7\x81\xbf\x01\x00\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00\xc4\x8b\xae\xf4\x00\xdf\x1e ]h\x06\xdc\x13@\x18\x88\x03\x00(\x11'
        sequence_number, sending_time, seconds_since_epoch, nanoseconds_correction = Payload._parse_udp_payload(
            udp_payload)

        expected_sequence_number = 28723643
        expected_sending_time = 1567098588322950040
        expected_seconds_since_epoch = 3691407453
        expected_nanoseconds_correction = 2283290643

        self.assertEqual(sequence_number, expected_sequence_number)
        self.assertEqual(sending_time, expected_sending_time)
        self.assertEqual(seconds_since_epoch, expected_seconds_since_epoch)
        self.assertEqual(nanoseconds_correction, expected_nanoseconds_correction)

    def test_failed_payload(self):
        udp_payload = b'\xbb'
        with self.assertRaises(IncompleteUDPPayload):
            sequence_number, sending_time, seconds_since_epoch, nanoseconds_correction = Payload._parse_udp_payload(
                udp_payload)


class TestPayloadComparison(unittest.TestCase):

    def setUp(self):
        self.test_file_path_a = os.path.abspath(
            os.path.join(os.path.dirname(__file__), 'test_data',
                         'test1.pcap.xz')
        )
        self.test_file_path_b = os.path.abspath(
            os.path.join(os.path.dirname(__file__), 'test_data',
                         'test2.pcap.xz')
        )

    def test_directory_not_exists(self):
        directory_path = '/non/existent/path'
        with self.assertRaises(DirError):
            payload_comparer._find_and_prepare_pcap_files(directory_path)

    def test_path_is_not_a_dir(self):
        directory_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), 'test_data', 'only_1_file', 'file_path')
        )
        with self.assertRaises(DirError):
            payload_comparer._find_and_prepare_pcap_files(directory_path)

    def test_not_enough_pcap_files(self):
        directory_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), 'test_data')
        )
        a, b = payload_comparer._find_and_prepare_pcap_files(directory_path)
        payload_instance_a = Payload(self.test_file_path_a)
        self.assertEqual(a.get_time_information, payload_instance_a.get_time_information)

    def test_successful_path(self):
        directory_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), 'test_data', 'only_1_file')
        )
        with self.assertRaises(ValueError):
            payload_comparer._find_and_prepare_pcap_files(directory_path)

    def test_find_prepare_pcap_files(self):
        payload_instance_a = Payload(self.test_file_path_a)
        payload_instance_b = Payload(self.test_file_path_b)
        expected_stats = {'total_packets_a': 22627, 'total_packets_b': 22627, 'extra_packets_in_a': 0,
                          'extra_packets_in_b': 0,
                          'avg_speed_advantage_a': 1372485186.5027933, 'avg_speed_advantage_b': 1408239965.7511413,
                          'number_of_packets_faster_in_a': 11456, 'number_of_packets_faster_in_b': 11171}
        comparison_stats = payload_comparer.packet_comparison(payload_instance_a, payload_instance_b)
        self.assertEqual(expected_stats, comparison_stats)

    def test_packet_compare(self):
        payload_instance_a = Payload(self.test_file_path_a)
        payload_instance_b = Payload(self.test_file_path_b)
        expected_stats = {'total_packets_a': 22627, 'total_packets_b': 22627, 'extra_packets_in_a': 0,
                          'extra_packets_in_b': 0,
                          'avg_speed_advantage_a': 1372485186.5027933, 'avg_speed_advantage_b': 1408239965.7511413,
                          'number_of_packets_faster_in_a': 11456, 'number_of_packets_faster_in_b': 11171}
        comparison_stats = payload_comparer.packet_comparison(payload_instance_a, payload_instance_b)
        self.assertEqual(expected_stats, comparison_stats)

if __name__ == '__main__':
    unittest.main()
