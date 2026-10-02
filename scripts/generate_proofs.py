"""Create local visual proof images from real generated artifacts (no fabricated results)."""
from __future__ import annotations
import csv,json,os,sqlite3,textwrap
from pathlib import Path
from PIL import Image,ImageDraw,ImageFont
ROOT=Path(__file__).resolve().parents[1]; OUT=ROOT/'screenshots'
FONT='/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf'; BOLD='/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf'
def font(n,b=False): return ImageFont.truetype(BOLD if b else FONT,n)
def render(name,title,command,content,accent='#4de2c5'):
    im=Image.new('RGB',(1440,900),'#071019'); d=ImageDraw.Draw(im)
    d.rounded_rectangle((54,48,1386,852),radius=18,fill='#0c1924',outline='#203746',width=2)
    d.rounded_rectangle((54,48,1386,118),radius=18,fill='#102330'); d.rectangle((54,96,1386,118),fill='#102330')
    for i,c in enumerate(['#ff6b7a','#f9b84b','#4de2c5']): d.ellipse((82+i*30,74,97+i*30,89),fill=c)
    d.text((190,70),title,font=font(22,True),fill='#dfe8f4'); d.text((82,139),'$ '+command,font=font(17),fill=accent)
    y=185
    for raw in str(content).splitlines():
        parts=textwrap.wrap(raw,width=117,replace_whitespace=False,drop_whitespace=False) or ['']
        for line in parts:
            if y>817: d.text((82,y),'… output truncated; source artifact retained in reports/',font=font(15),fill='#f9b84b'); break
            d.text((82,y),line,font=font(15),fill='#9bb0bf'); y+=22
        if y>817: break
    im.save(OUT/name)
def structure():
    keep=[]
    for p in sorted(ROOT.rglob('*')):
        rel=p.relative_to(ROOT)
        if any(x in rel.parts for x in ['node_modules','dist','__pycache__','.pytest_cache']): continue
        if len(rel.parts)<=2 and (p.is_dir() or p.suffix in {'.py','.md','.json','.csv','.jsx','.js'}): keep.append(('  '*(len(rel.parts)-1))+('├── ')+rel.name+('/' if p.is_dir() else ''))
    return '\n'.join(keep[:65])
normal=json.loads((ROOT/'reports/proof_normal_response.json').read_text()); suspicious=json.loads((ROOT/'reports/proof_suspicious_response.json').read_text())
render('01_project_structure.png','Project Structure','find . -maxdepth 2 -not -path "*/node_modules/*"',structure())
with (ROOT/'data/network_traffic.csv').open() as f: rows=list(csv.reader(f))[:6]
render('03_synthetic_dataset.png','Synthetic Dataset — 5,000 records','python -m simulator.generate_dataset --count 5000', '\n'.join(' | '.join(r) for r in rows))
first=json.loads((ROOT/'reports/simulation_console.jsonl').read_text().splitlines()[0]); render('04_traffic_simulator.png','Traffic Simulator (data only)','python -m simulator.traffic_simulator --mode mixed --speed fast --count 5',json.dumps(first,indent=2)[:7000])
render('05_normal_traffic.png','Normal HTTPS Record — Actual Result','POST /api/flows  # PROOF-NORMAL-001',json.dumps({k:normal[k] for k in ['flow_id','classification','severity','risk_score','rule_matches','anomaly_score','ml','alert']},indent=2))
render('06_suspicious_traffic.png','Suspicious Synthetic Record — Actual Result','POST /api/flows  # PROOF-SUSPICIOUS-001',json.dumps({k:suspicious[k] for k in ['flow_id','classification','severity','risk_score','anomaly_score','ml']},indent=2))
render('07_feature_extraction.png','Network Feature Extraction','extract_network_features(flow)',json.dumps(suspicious['features'],indent=2))
render('08_signature_rule_triggered.png','Signature Rules Triggered','RuleEngine.analyze_flow(flow, features)',json.dumps(suspicious['rule_matches'],indent=2))
render('09_anomaly_score.png','Statistical Anomaly Score','StatisticalAnomalyDetector.calculate_anomaly_score(features)',json.dumps({'score':suspicious['anomaly_score'],'components':suspicious['anomaly_details']},indent=2))
render('10_hybrid_risk_score.png','Hybrid Risk Score — Configurable 40/30/30','calculate_risk_score(rule, anomaly, ml)',json.dumps({k:suspicious[k] for k in ['classification','severity','risk_score','anomaly_score','ml']},indent=2))
render('11_alert_generated.png','SOC Alert Generated','generate_alert(flow, risk, rule_matches, anomaly, ml)',json.dumps(suspicious['alert'],indent=2))
metrics=(ROOT/'reports/ml_metrics.json').read_text(); render('20_ml_evaluation.png','Measured ML Evaluation','python -m ml.train_model',metrics)
render('22_automated_tests.png','Automated Test Execution','pytest -q',(ROOT/'reports/pytest_console.txt').read_text())
api=json.loads((ROOT/'reports/api_api_alerts_limit-3.json').read_text()); render('23_api_response.png','Authenticated API Response','GET /api/alerts?limit=3',json.dumps(api,indent=2)[:12000])
con=sqlite3.connect(ROOT/'data/ids.db'); lines=[]
for table in ['network_flows','alerts','rules','incident_notes','model_results','audit_logs']:
 lines.append(f'{table}: {con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]} rows')
lines.append('\nRecent alerts:')
for r in con.execute('SELECT alert_id,flow_id,severity,risk_score,status FROM alerts ORDER BY created_at DESC LIMIT 8'): lines.append(' | '.join(map(str,r)))
con.close(); render('24_database_records.png','SQLite Security Database','sqlite3 data/ids.db  # counts and recent alerts','\n'.join(lines))
# Real browser screenshot crops for chart/status/note evidence.
im=Image.open(OUT/'12_soc_dashboard.png'); w,h=im.size
crops={'13_traffic_over_time.png':(260,300,1030,555),'14_protocol_distribution.png':(1010,555,1375,770),'15_severity_distribution.png':(260,555,640,770),'16_top_alert_types.png':(640,555,1010,770)}
for name,box in crops.items(): im.crop(box).save(OUT/name)
inv=Image.open(OUT/'17_alert_investigation.png'); inv.crop((1020,370,1410,680)).save(OUT/'18_analyst_notes.png'); inv.crop((1020,235,1410,385)).save(OUT/'19_incident_status.png')
print('Generated local proof images in',OUT)
