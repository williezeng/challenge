import lzma
from scapy.all import rdpcap, UDP
from payload_exceptions import PcapFileError
import struct

# TODO: add wrapper that looks at a full directory


class Payload(object):
    """
    Parses UDP payload from a single pcap file
    """
    def __init__(self, file_path):
        if file_path.endswith(".xz"):
            self.uncompress_xz_to_pcap(file_path, file_path[:-3])
            self.pcap_path = file_path[:-3]  # Update to use the uncompressed file
        else:
            raise PcapFileError('Unable to obtain a .pcap file')

    @staticmethod
    def uncompress_xz_to_pcap(xz_path, pcap_output_path):
        with lzma.open(xz_path, 'rb') as f:
            file_content = f.read()
        with open(pcap_output_path, 'wb') as f:
            f.write(file_content)

    def read_pcap_file(self):
        packets = rdpcap(self.pcap_path)
        return packets

    def get_time_information(self):
        time_information = {}
        packets = self.read_pcap_file()
        for packet in packets:
            if UDP in packet:
                udp_payload = bytes(packet[UDP].payload)
                if udp_payload:
                    sequence_number, sending_time, seconds_since_epoch, nanoseconds_correction = self.parse_udp_payload(udp_payload)
                    time_information[sequence_number] = [sending_time, seconds_since_epoch, nanoseconds_correction]
        return time_information

    @staticmethod
    def parse_udp_payload(udp_payload):
        # The header is 12 bytes:
        #    sequence_number = 4 bytes
        #    sending_time = 8 bytes
        # The trailer is 20 bytes:
        #    offset = 8 bytes
        #    seconds_since_epoch = 4 bytes
        #    nano_second_correction = 4 bytes
        #    unknown = 4 bytes
        # '<' = little-endian, 'I' = unsigned 32 bit int, 'Q' = unsigned 64 bit int
        assert len(udp_payload) >= 32, "UDP payload is too short to contain the required structure."
        header = udp_payload[0:12]
        sequence_number = struct.unpack_from('<I', header, 0)[0]
        sending_time = struct.unpack_from('<Q', header, 4)[0]
        trailer_start = len(udp_payload) - 20
        metamako_trailer = udp_payload[trailer_start:]
        seconds_since_epoch = struct.unpack_from('<I', metamako_trailer, 8)[0]
        nanoseconds_correction = struct.unpack_from('<I', metamako_trailer, 12)[0]
        return sequence_number, sending_time, seconds_since_epoch, nanoseconds_correction


