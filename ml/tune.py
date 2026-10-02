"""Threshold sweep from 0.30 to 0.80 for an auditable operating-point choice."""
from __future__ import annotations
import argparse, csv, joblib, pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from ml.train_model import prepare, metrics

def sweep(dataset="data/network_traffic.csv",model_path="models/ids_rf.joblib",output="reports/threshold_sweep.csv"):
    X,y=prepare(pd.read_csv(dataset)); _,Xte,_,yte=train_test_split(X,y,test_size=.2,random_state=42,stratify=y); bundle=joblib.load(model_path); p=bundle["model"].predict_proba(Xte)[:,1]
    rows=[]
    for i in range(30,81,5):
        threshold=i/100; result=metrics(yte,(p>=threshold).astype(int),p); rows.append({"threshold":threshold,**{k:v for k,v in result.items() if k!="confusion_matrix"}})
    Path(output).parent.mkdir(parents=True,exist_ok=True)
    with open(output,"w",newline="",encoding="utf-8") as f: writer=csv.DictWriter(f,fieldnames=rows[0]); writer.writeheader(); writer.writerows(rows)
    return rows
if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--dataset",default="data/network_traffic.csv"); p.add_argument("--model",default="models/ids_rf.joblib"); p.add_argument("--output",default="reports/threshold_sweep.csv"); a=p.parse_args()
    for row in sweep(a.dataset,a.model,a.output): print(row)
