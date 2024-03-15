class PcapFileError(Exception):
    """Exception raised for errors in the input pcap file."""
    pass


class IncompleteUDPPayload(Exception):
    """Exception raised for incomplete UDP payloads."""
    pass


class DirError(Exception):
    """Exception raised for errors in the dir path"""
    pass
