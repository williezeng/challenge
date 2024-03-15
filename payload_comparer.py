import argparse
from payload_interface import Payload
from payload_exceptions import PcapFileError, DirError
import os
import json
import glob


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


def packet_comparison(payload_a, payload_b):
    packet_comparison_stats = {}
    time_diffs_when_a_faster = []
    time_diffs_when_b_faster = []
    parsed_packets_a = payload_a.get_time_information
    parsed_packets_b = payload_b.get_time_information

    packet_comparison_stats['total_packets_a'] = len(parsed_packets_a)
    packet_comparison_stats['total_packets_b'] = len(parsed_packets_b)
    packet_comparison_stats['extra_packets_in_a'] = len(set(parsed_packets_a) - set(parsed_packets_b))
    packet_comparison_stats['extra_packets_in_b'] = len(set(parsed_packets_b) - set(parsed_packets_a))

    packets_in_both = set(parsed_packets_a).intersection(set(parsed_packets_b))
    for seq_number in packets_in_both:
        timestamp_a = parsed_packets_a[seq_number][0] + parsed_packets_a[seq_number][2]
        timestamp_b = parsed_packets_b[seq_number][0] + parsed_packets_b[seq_number][2]
        if timestamp_a < timestamp_b:
            time_diffs_when_a_faster.append(timestamp_b - timestamp_a)
        elif timestamp_b < timestamp_a:
            time_diffs_when_b_faster.append(timestamp_a - timestamp_b)
    packet_comparison_stats['avg_speed_advantage_a'] = sum(time_diffs_when_a_faster) / len(time_diffs_when_a_faster) if time_diffs_when_a_faster else 0
    packet_comparison_stats['avg_speed_advantage_b'] = sum(time_diffs_when_b_faster) / len(time_diffs_when_b_faster) if time_diffs_when_b_faster else 0
    packet_comparison_stats['number_of_packets_faster_in_a'] = len(time_diffs_when_a_faster)
    packet_comparison_stats['number_of_packets_faster_in_b'] = len(time_diffs_when_b_faster)
    return packet_comparison_stats


def main():
    # Setup argparse
    parser = argparse.ArgumentParser(description="Analyzes and compares pcap files in a given directory.")
    parser.add_argument("--directory_path", required=True, help="The path to the directory containing .xz pcap files for comparison.")
    parser.add_argument("--debug", action='store_true', help="If specified, dump packets to files in the directory_path.")

    args = parser.parse_args()

    try:
        payload_a, payload_b = _find_and_prepare_pcap_files(args.directory_path)
    except (DirError, ValueError) as e:
        print(f"Error: {e}")
        return

    if args.debug:
        parsed_packets_a = payload_a.get_time_information
        file_name = os.path.join(args.directory_path, 'packet_a.json')
        with open(file_name, "w") as fd:
            json.dump(parsed_packets_a, fd, indent=4)

        parsed_packets_b = payload_b.get_time_information
        file_name = os.path.join(args.directory_path, 'packet_b.json')
        with open(file_name, "w") as fd:
            json.dump(parsed_packets_b, fd, indent=4)

    comparison_stats = packet_comparison(payload_a, payload_b)
    print(json.dumps(comparison_stats, indent=4))


if __name__ == '__main__':
    main()
