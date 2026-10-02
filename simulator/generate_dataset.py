"""Create a deterministic, entirely synthetic flow dataset using RFC 5737 addresses."""
from __future__ import annotations
import argparse, csv, random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

COLUMNS = ["flow_id","timestamp","source_ip","destination_ip","source_port","destination_port","protocol","packet_count","byte_count","duration_seconds","connection_count","failed_connection_count","syn_count","rst_count","average_packet_size","label","scenario_type"]
NORMAL_SCENARIOS = ["NORMAL_WEB","NORMAL_DNS","NORMAL_SSH","NORMAL_EMAIL","NORMAL_DATABASE"]
SUSPICIOUS_SCENARIOS = ["HIGH_CONNECTION_RATE","REPEATED_FAILED_CONNECTIONS","MULTI_PORT_PROBING_PATTERN","SYN_HEAVY_PATTERN","UNUSUAL_PORT_ACTIVITY","HIGH_TRAFFIC_VOLUME","HIGH_DNS_QUERY_RATE","GENERIC_C2_LIKE_PATTERN"]

def doc_ip(prefix: str, rng: random.Random) -> str:
    return f"{prefix}.{rng.randint(1,254)}"

def make_record(index: int, scenario: str, rng: random.Random, start: datetime) -> dict:
    normal = scenario.startswith("NORMAL_")
    source_ip = doc_ip("192.0.2", rng)
    destination_ip = doc_ip(rng.choice(["198.51.100","203.0.113"]), rng)
    src_port = rng.randint(1024,65535)
    protocol, dport = "TCP", 443
    packets, bytes_, duration, connections, failed, syn, rst = rng.randint(8,120), 0, rng.uniform(.2,25), rng.randint(1,8), 0, rng.randint(1,4), 0
    if scenario == "NORMAL_WEB": dport=443; bytes_=rng.randint(4_000,180_000)
    elif scenario == "NORMAL_DNS": protocol="UDP"; dport=53; packets=rng.randint(1,8); bytes_=rng.randint(90,4_000); duration=rng.uniform(.01,1.2); syn=0
    elif scenario == "NORMAL_SSH": dport=22; bytes_=rng.randint(2_000,85_000); duration=rng.uniform(1,90)
    elif scenario == "NORMAL_EMAIL": dport=rng.choice([25,465,587,993]); bytes_=rng.randint(3_000,240_000)
    elif scenario == "NORMAL_DATABASE": dport=rng.choice([3306,5432]); bytes_=rng.randint(2_000,350_000)
    elif scenario == "HIGH_CONNECTION_RATE": connections=rng.randint(160,450); duration=rng.uniform(.5,4); failed=rng.randint(0,8); packets=rng.randint(200,900); bytes_=rng.randint(100_000,1_500_000); syn=rng.randint(80,180)
    elif scenario == "REPEATED_FAILED_CONNECTIONS": dport=rng.choice([22,443]); connections=rng.randint(25,75); failed=rng.randint(15,25); failed=min(failed,connections); packets=rng.randint(35,180); bytes_=rng.randint(3_000,90_000); duration=rng.uniform(2,25); syn=rng.randint(12,35); rst=rng.randint(8,25)
    elif scenario == "MULTI_PORT_PROBING_PATTERN": dport=rng.randint(1,1023); connections=rng.randint(30,90); packets=rng.randint(45,220); bytes_=rng.randint(5_000,80_000); duration=rng.uniform(.5,8); syn=rng.randint(25,80); rst=rng.randint(5,30)
    elif scenario == "SYN_HEAVY_PATTERN": dport=rng.choice([80,443]); packets=rng.randint(70,280); syn=int(packets*rng.uniform(.78,.96)); connections=rng.randint(45,160); bytes_=rng.randint(7_000,110_000); duration=rng.uniform(.2,3); rst=rng.randint(0,5)
    elif scenario == "UNUSUAL_PORT_ACTIVITY": dport=rng.choice([4444,5555,8088,31337,65000]); packets=rng.randint(10,100); bytes_=rng.randint(1_000,250_000); connections=rng.randint(1,15)
    elif scenario == "HIGH_TRAFFIC_VOLUME": dport=443; packets=rng.randint(6_000,25_000); bytes_=rng.randint(6_000_000,40_000_000); duration=rng.uniform(1,20); connections=rng.randint(2,40); syn=rng.randint(2,20)
    elif scenario == "HIGH_DNS_QUERY_RATE": protocol="UDP"; dport=53; packets=rng.randint(300,900); bytes_=rng.randint(30_000,400_000); duration=rng.uniform(.5,4); connections=rng.randint(40,180); failed=0; syn=0; rst=0
    elif scenario == "GENERIC_C2_LIKE_PATTERN": dport=rng.choice([4444,5555,8088,65000]); packets=rng.randint(8,45); bytes_=rng.randint(800,25_000); duration=rng.uniform(30,240); connections=rng.randint(2,12); syn=rng.randint(1,4)
    else: raise ValueError(f"unknown scenario: {scenario}")
    if bytes_ == 0: bytes_ = packets*rng.randint(100,1400)
    return {
        "flow_id":f"FLOW-{index:06d}","timestamp":(start+timedelta(seconds=index*3)).isoformat(),
        "source_ip":source_ip,"destination_ip":destination_ip,"source_port":src_port,"destination_port":dport,"protocol":protocol,
        "packet_count":packets,"byte_count":bytes_,"duration_seconds":round(duration,4),"connection_count":connections,
        "failed_connection_count":failed,"syn_count":syn,"rst_count":rst,"average_packet_size":round(bytes_/max(packets,1),2),
        "label":"NORMAL" if normal else "SUSPICIOUS","scenario_type":scenario,
    }

def generate_dataset(count: int = 5000, output: str | Path = "data/network_traffic.csv", seed: int = 42) -> Path:
    if count < 5000: raise ValueError("the project dataset must contain at least 5,000 records")
    rng=random.Random(seed); start=datetime(2026,1,1,tzinfo=timezone.utc); records=[]
    # A realistic class imbalance: 72% baseline and 28% suspicious synthetic records.
    for i in range(count):
        scenario=rng.choice(NORMAL_SCENARIOS if i < int(count*.72) else SUSPICIOUS_SCENARIOS)
        records.append(make_record(i+1,scenario,rng,start))
    rng.shuffle(records)
    output=Path(output); output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("w",newline="",encoding="utf-8") as handle:
        writer=csv.DictWriter(handle,fieldnames=COLUMNS); writer.writeheader(); writer.writerows(records)
    return output

def main():
    parser=argparse.ArgumentParser(description="Generate safe synthetic IDS flow records (no packets are sent).")
    parser.add_argument("--count",type=int,default=5000); parser.add_argument("--output",default="data/network_traffic.csv"); parser.add_argument("--seed",type=int,default=42)
    args=parser.parse_args(); path=generate_dataset(args.count,args.output,args.seed); print(f"Generated {args.count} synthetic flow records: {path}")
if __name__ == "__main__": main()
