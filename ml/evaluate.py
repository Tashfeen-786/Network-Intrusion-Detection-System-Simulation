"""Recalculate held-out metrics and save a confusion-matrix proof image."""
from __future__ import annotations
import argparse, json
from pathlib import Path
import joblib, pandas as pd
from sklearn.metrics import ConfusionMatrixDisplay
from sklearn.model_selection import train_test_split
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from ml.train_model import prepare, metrics

def evaluate(dataset="data/network_traffic.csv",model_path="models/ids_rf.joblib",output="reports/evaluation.json",image="screenshots/21_confusion_matrix.png"):
    X,y=prepare(pd.read_csv(dataset)); _,Xte,_,yte=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)
    bundle=joblib.load(model_path); proba=bundle["model"].predict_proba(Xte)[:,1]; pred=(proba>=bundle.get("threshold",.5)).astype(int)
    result={"model":bundle.get("model_name"),**metrics(yte,pred,proba),"evaluated_records":len(yte)}
    Path(output).parent.mkdir(parents=True,exist_ok=True); Path(output).write_text(json.dumps(result,indent=2),encoding="utf-8")
    display=ConfusionMatrixDisplay.from_predictions(yte,pred,display_labels=["NORMAL","SUSPICIOUS"],cmap="Blues",colorbar=False)
    display.ax_.set_title("Held-out ML Confusion Matrix"); plt.tight_layout(); Path(image).parent.mkdir(parents=True,exist_ok=True); plt.savefig(image,dpi=160); plt.close()
    return result
if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--dataset",default="data/network_traffic.csv"); p.add_argument("--model",default="models/ids_rf.joblib"); p.add_argument("--output",default="reports/evaluation.json"); p.add_argument("--image",default="screenshots/21_confusion_matrix.png"); a=p.parse_args(); print(json.dumps(evaluate(a.dataset,a.model,a.output,a.image),indent=2))
