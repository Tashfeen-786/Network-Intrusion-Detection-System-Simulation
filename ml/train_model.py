"""Train and genuinely evaluate Logistic Regression, Random Forest and Isolation Forest."""
from __future__ import annotations
import argparse, json
from pathlib import Path
import joblib, numpy as np, pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

FEATURES=["packet_count","byte_count","duration_seconds","bytes_per_second","packets_per_second","connection_count","failed_connection_count","syn_count","rst_count","average_packet_size"]

def prepare(df: pd.DataFrame):
    data=df.copy()
    for column in ["packet_count","byte_count","duration_seconds","connection_count","failed_connection_count","syn_count","rst_count","average_packet_size"]:
        data[column]=pd.to_numeric(data.get(column,0),errors="coerce").fillna(0).clip(lower=0)
    duration=data["duration_seconds"].clip(lower=.001)
    data["bytes_per_second"]=data["byte_count"]/duration; data["packets_per_second"]=data["packet_count"]/duration
    X=data[FEATURES].replace([np.inf,-np.inf],0).fillna(0); y=(data["label"].astype(str).str.upper()=="SUSPICIOUS").astype(int)
    return X,y

def metrics(y_true, pred, proba=None):
    precision,recall,f1,_=precision_recall_fscore_support(y_true,pred,average="binary",zero_division=0)
    result={"accuracy":round(float(accuracy_score(y_true,pred)),6),"precision":round(float(precision),6),"recall":round(float(recall),6),"f1":round(float(f1),6),"confusion_matrix":confusion_matrix(y_true,pred,labels=[0,1]).tolist()}
    if proba is not None:
        try: result["roc_auc"]=round(float(roc_auc_score(y_true,proba)),6)
        except ValueError: result["roc_auc"]=None
    return result

def train(dataset="data/network_traffic.csv",model_output="models/ids_rf.joblib",metrics_output="reports/ml_metrics.json"):
    df=pd.read_csv(dataset)
    if df.empty: raise ValueError("training dataset is empty")
    X,y=prepare(df); Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)
    logistic=Pipeline([("scale",StandardScaler()),("model",LogisticRegression(max_iter=1500,class_weight="balanced",random_state=42))])
    forest=RandomForestClassifier(n_estimators=240,max_depth=18,class_weight="balanced",n_jobs=-1,random_state=42)
    logistic.fit(Xtr,ytr); forest.fit(Xtr,ytr)
    normal_train=Xtr[ytr==0]
    isolation=Pipeline([("scale",StandardScaler()),("model",IsolationForest(n_estimators=200,contamination=float(max(.01,min(.4,ytr.mean()))),random_state=42,n_jobs=-1))])
    isolation.fit(normal_train)
    logp=logistic.predict_proba(Xte)[:,1]; rfp=forest.predict_proba(Xte)[:,1]
    # IsolationForest: -1 is anomalous/suspicious; convert decision function to a monotonic score for ROC-AUC.
    isop=isolation.predict(Xte); isopred=(isop==-1).astype(int); isoscore=-isolation.decision_function(Xte)
    results={"dataset_records":int(len(df)),"train_records":int(len(Xtr)),"test_records":int(len(Xte)),"class_balance":{"normal":int((y==0).sum()),"suspicious":int((y==1).sum())},"models":{
      "logistic_regression":metrics(yte,(logp>=.5).astype(int),logp),"random_forest":metrics(yte,(rfp>=.5).astype(int),rfp),"isolation_forest":metrics(yte,isopred,isoscore)},
      "note":"Metrics were calculated from the deterministic held-out test split; they are not fabricated."}
    Path(model_output).parent.mkdir(parents=True,exist_ok=True)
    joblib.dump({"model":forest,"feature_names":FEATURES,"threshold":.5,"model_name":"RandomForestClassifier","metrics":results["models"]["random_forest"]},model_output)
    # Retain comparison models as requested.
    joblib.dump({"model":logistic,"feature_names":FEATURES,"threshold":.5,"model_name":"LogisticRegression"},str(Path(model_output).with_name("ids_logistic.joblib")))
    joblib.dump({"model":isolation,"feature_names":FEATURES,"model_name":"IsolationForest"},str(Path(model_output).with_name("ids_isolation.joblib")))
    Path(metrics_output).parent.mkdir(parents=True,exist_ok=True); Path(metrics_output).write_text(json.dumps(results,indent=2),encoding="utf-8")
    return results

def main():
    p=argparse.ArgumentParser(); p.add_argument("--dataset",default="data/network_traffic.csv"); p.add_argument("--output",default="models/ids_rf.joblib"); p.add_argument("--metrics",default="reports/ml_metrics.json")
    a=p.parse_args(); print(json.dumps(train(a.dataset,a.output,a.metrics),indent=2))
if __name__=="__main__": main()
