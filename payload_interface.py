import os
from scapy.all import rdpcap
from payload_exceptions import PcapFileError
# TODO: Add uncompression

class Payload(object):
    def __init__(self, dir_path):
        self.file_paths = self.find_pcaps(dir_path)
        assert len(self.file_paths) != 0, "Found 0 .pcap files"
        self.data_a = None
        self.data_b = None
        if len(self.file_paths) == 1:
            self.data_a = self.read_file(self.file_paths[0])
        elif len(self.file_paths) == 2:
            self.data_a = self.read_file(self.file_paths[0])
            self.data_b = self.read_file(self.file_paths[1])
        else:
            raise PcapFileError("Found more than 2 .pcap files")

    @staticmethod
    def find_pcaps(dir_path):
        pcap_files = []
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                if file.endswith(".pcap"):
                    pcap_files.append(os.path.join(root, file))
        return pcap_files

    @staticmethod
    def read_file(file_path):
        try:
            pcap_data = rdpcap(file_path)
            return pcap_data
        except FileNotFoundError:
            print("File not found:", file_path)
        except Exception as e:
            print("An error occurred:", e)
        return None

