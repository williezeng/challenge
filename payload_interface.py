import lzma
from scapy.all import rdpcap, UDP
from payload_exceptions import PcapFileError, IncompleteUDPPayload
import struct


class Payload(object):
    """
    Parses UDP payload from a single pcap file
    """
    def __init__(self, file_path):
        self._file_path = file_path
        self._pcap_path = None
        self._ensure_pcap()

    def _ensure_pcap(self):
        if self._file_path.endswith(".xz"):
            self._pcap_path = self._file_path[:-3]
            self._uncompress_xz_to_pcap(self._file_path, self._pcap_path)
        else:
            raise PcapFileError('Unsupported file format.')

    @staticmethod
    def _uncompress_xz_to_pcap(xz_path, pcap_output_path):
        """
        Decompresses an .xz file to a pcap file.

        Args:
            xz_path (str): The path to the .xz compressed file.
            pcap_output_path (str): The path where the decompressed pcap file should be saved.
        """
        with lzma.open(xz_path, 'rb') as f:
            file_content = f.read()
        with open(pcap_output_path, 'wb') as f:
            f.write(file_content)

    def _read_pcap_file(self):
        packets = rdpcap(self._pcap_path)
        return packets

    @property
    def get_time_information(self):
        """
        Extracts time information from each UDP packet in the pcap file.

        Returns:
            dict: A dictionary mapping sequence numbers to a list containing
                  sending time, seconds since epoch, and nanoseconds correction.
        """
        time_information = {}
        packets = self._read_pcap_file()
        for packet in packets:
            if UDP in packet:
                udp_payload = bytes(packet[UDP].payload)
                if udp_payload:
                    sequence_number, sending_time, seconds_since_epoch, nanoseconds_correction = self._parse_udp_payload(udp_payload)
                    time_information[sequence_number] = [sending_time, seconds_since_epoch, nanoseconds_correction]
        return time_information

    @staticmethod
    def _parse_udp_payload(udp_payload):
        """
        Parses the UDP payload to extract sequence number, sending time, and time correction information.
        Args:
            udp_payload (bytes): The UDP payload from which to extract information.
        Returns:
            tuple: Contains sequence number, sending time, seconds since epoch, and nanoseconds correction.
        Raises:
            IncompleteUDPPayload: If the payload is too short to contain the required structured information.


        The header is 12 bytes:
            sequence_number = 4 bytes
            sending_time = 8 bytes
        The trailer is 20 bytes:
            offset = 8 bytes
            seconds_since_epoch = 4 bytes
            nano_second_correction = 4 bytes
            unknown = 4 bytes
         '<' = little-endian, 'I' = unsigned 32 bit int, 'Q' = unsigned 64 bit int

        """
        if len(udp_payload) <= 32:
            raise IncompleteUDPPayload("UDP payload is too short to contain the required structure.")
        header = udp_payload[0:12]
        sequence_number = struct.unpack_from('<I', header, 0)[0]
        sending_time = struct.unpack_from('<Q', header, 4)[0]
        trailer_start = len(udp_payload) - 20
        metamako_trailer = udp_payload[trailer_start:]
        seconds_since_epoch = struct.unpack_from('<I', metamako_trailer, 8)[0]
        nanoseconds_correction = struct.unpack_from('<I', metamako_trailer, 12)[0]
        return sequence_number, sending_time, seconds_since_epoch, nanoseconds_correction


