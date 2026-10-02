"""Near-real-time flow DATA simulator. It never opens raw sockets or sends packets."""
from __future__ import annotations
import argparse, json, random, sys, time
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from uuid import uuid4

NORMAL=["NORMAL_WEB","NORMAL_DNS","NORMAL_SSH","NORMAL_EMAIL","NORMAL_DATABASE"]
SUSPICIOUS=["HIGH_CONNECTION_RATE","REPEATED_FAILED_CONNECTIONS","MULTI_PORT_PROBING_PATTERN","SYN_HEAVY_PATTERN","UNUSUAL_PORT_ACTIVITY","HIGH_TRAFFIC_VOLUME"]

def generate_flow(mode="mixed", rng=None):
    rng=rng or random.Random(); scenario=rng.choice(NORMAL if mode=="normal" or rng.random()<.70 else SUSPICIOUS)
    try:
        from simulator.generate_dataset import make_record
    except ModuleNotFoundError:  # Supports: python simulator/traffic_simulator.py
        from generate_dataset import make_record
    row=make_record(rng.randint(1,999999),scenario,rng,datetime.now(timezone.utc))
    row["flow_id"]="LIVE-"+uuid4().hex[:12].upper(); row["timestamp"]=datetime.now(timezone.utc).isoformat()
    row["unique_destination_ports"] = rng.randint(25,70) if scenario=="MULTI_PORT_PROBING_PATTERN" else 1
    row["unique_destination_ips"] = rng.randint(8,30) if scenario in {"HIGH_CONNECTION_RATE","MULTI_PORT_PROBING_PATTERN"} else 1
    return row

def post_flow(url, flow, api_key):
    body=json.dumps(flow).encode(); request=Request(url,data=body,headers={"Content-Type":"application/json","X-API-Key":api_key},method="POST")
    with urlopen(request,timeout=5) as response: return json.loads(response.read())

def main():
    p=argparse.ArgumentParser(description="Continuously emit synthetic flow records; no network packets are generated.")
    p.add_argument("--mode",choices=["normal","mixed"],default="mixed"); p.add_argument("--speed",choices=["slow","fast"],default="slow")
    p.add_argument("--count",type=int,default=0,help="0 means continuous"); p.add_argument("--api-url",default="http://127.0.0.1:8000/api/flows")
    p.add_argument("--api-key",default="dev-analyst-key"); p.add_argument("--stdout-only",action="store_true"); p.add_argument("--seed",type=int)
    args=p.parse_args(); delay=2.0 if args.speed=="slow" else .15; rng=random.Random(args.seed); sent=0
    print("SAFE MODE: generating statistical flow data only; no packets are sent.",file=sys.stderr)
    try:
        while args.count==0 or sent<args.count:
            flow=generate_flow(args.mode,rng)
            if args.stdout_only: result={"flow":flow}
            else:
                try: result=post_flow(args.api_url,flow,args.api_key)
                except (URLError,HTTPError) as exc: result={"error":str(exc),"flow":flow}
            print(json.dumps(result,sort_keys=True)); sent+=1
            if args.count==0 or sent<args.count: time.sleep(delay)
    except KeyboardInterrupt: print("Simulation stopped safely.",file=sys.stderr)
if __name__=="__main__": main()
