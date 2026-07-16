"""
Offline validation harness: replays synthetic pcaps through the real
PacketAnalyzer.process_packet() pipeline (no root / live interface
needed) and reports what each flow was classified as. Useful both as a
sanity check after changes and as a demo for anyone reviewing the repo.
"""
import sys
import pyshark

sys.path.insert(0, '.')
from app import PacketAnalyzer  # noqa: E402


def run_scenario(name, pcap_path, config_path="config.json"):
    analyzer = PacketAnalyzer(config_path)
    cap = pyshark.FileCapture(pcap_path, use_json=True, include_raw=True)
    outcomes = []
    for packet in cap:
        analyzer.process_packet(packet)
    cap.close()
    print(f"\n=== {name} ({pcap_path}) ===")
    for flow_id, flow in analyzer.flows.items():
        print(f"  {flow.src_ip:15s} -> {flow.dst_ip:15s}:{flow.dst_port:<5d} "
              f"proto={flow.protocol_type:5s} flag={flow.flag:8s} "
              f"outcome={flow.outcome:12s} conf={flow.confidence:.2f}")
    outcomes = {f.outcome for f in analyzer.flows.values()}
    return outcomes


if __name__ == '__main__':
    results = {}
    results['normal'] = run_scenario("Normal web browsing", "normal.pcap")
    results['neptune'] = run_scenario("SYN flood (neptune)", "neptune.pcap")
    results['portsweep'] = run_scenario("Port scan (portsweep)", "portsweep.pcap")
    results['ipsweep'] = run_scenario("Host scan (ipsweep)", "ipsweep.pcap")
    results['smurf'] = run_scenario("ICMP flood (smurf)", "smurf.pcap")

    print("\n=== Summary ===")
    for scenario, outcomes in results.items():
        print(f"  {scenario:12s}: {sorted(outcomes)}")
