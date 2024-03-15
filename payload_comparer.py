from payload_interface import Payload
from payload_exceptions import PcapFileError, DirError
import os
import glob


class PayloadComparer(object):
    """
    Analyzes 2 pcap files for comparison
    """
    def __init__(self, directory_path):
        self.directory_path = directory_path
        self.payloadA, self.payloadB = self._find_and_prepare_pcap_files(self.directory_path)

    @staticmethod
    def _find_and_prepare_pcap_files(directory_path):
        if not os.path.exists(directory_path):
            raise DirError(f"The directory {directory_path} does not exist.")
        if not os.path.isdir(directory_path):
            raise DirError(f"The path {directory_path} is not a directory.")

        xz_files = glob.glob(os.path.join(directory_path, '*.xz'))
        if len(xz_files) < 2:
            raise ValueError("Not enough pcap files for comparison.")
        # deterministic way of comparing two packets
        all_files = sorted(xz_files)
        return Payload(all_files[0]), Payload(all_files[1])

    @staticmethod
    def faster_packets(payload_a, payload_b):
        # Assuming packet_stream_a and packet_stream_b are lists of udp_payloads for A and B, respectively
        # And assuming a modified parse_udp_payload function that directly returns a dictionary with parsed values

        parsed_packets_a = payload_a.get_time_information()
        parsed_packets_b = payload_b.get_time_information()

        extra_packets_in_a = set(parsed_packets_a) - set(parsed_packets_b)
        extra_packets_in_b = set(parsed_packets_b) - set(parsed_packets_a)
        packets_in_both = set(parsed_packets_a).intersection(set(parsed_packets_b))


        # Counters for comparison
        a_faster_count = 0
        b_faster_count = 0

        # Match packets by sequence number and compare timestamps
        for seq, packet_a in parsed_packets_a.items():
            packet_b = parsed_packets_b.get(seq)
            if packet_b:
                timestamp_a = packet_a['sending_time'] + packet_a['nanoseconds_correction']
                timestamp_b = packet_b['sending_time'] + packet_b['nanoseconds_correction']

                if timestamp_a < timestamp_b:
                    a_faster_count += 1
                elif timestamp_b < timestamp_a:
                    b_faster_count += 1

        return a_faster_count, b_faster_count


