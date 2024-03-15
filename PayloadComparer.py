from payload_interface import Payload
from payload_exceptions import PcapFileError
import os
import glob


class PayloadComparer(object):
    """
    Analyzes 2 pcap files for comparison
    """
    def __init__(self, directory_path):
        self.directory_path = directory_path
        self.payloadA, self.payloadB = self.find_and_prepare_pcap_files()

    def find_and_prepare_pcap_files(self):
        xz_files = glob.glob(os.path.join(self.directory_path, '*.xz'))
        all_files = sorted(xz_files)
        if len(all_files) < 2:
            raise ValueError("Not enough pcap files for comparison.")
        return Payload(all_files[0]), Payload(all_files[1])

