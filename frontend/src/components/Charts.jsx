const colors=['#4de2c5','#f9b84b','#8aa4ff','#ff6b7a','#b78cff','#56b4ff','#9bd67d','#fd8a5e'];
export function Bars({data=[],horizontal=false}){
 const max=Math.max(1,...data.map(d=>Number(d.value||d.alerts||0)));
 return <div className={`bars ${horizontal?'horizontal':''}`}>{data.length?data.slice(0,12).map((d,i)=><div className="bar-row" key={`${d.label}-${i}`}><span className="bar-label" title={d.label}>{d.label}</span><div className="bar-track"><i style={{width:`${Math.max(3,100*Number(d.value||d.alerts||0)/max)}%`,background:colors[i%colors.length]}}/></div><b>{Number(d.value||d.alerts||0).toLocaleString()}</b></div>):<Empty/>}</div>
}
export function Line({data=[],field='flows',color='#4de2c5'}){
 const values=data.map(d=>Number(d[field]||0)), max=Math.max(1,...values), min=Math.min(0,...values), w=500,h=125,pad=8;
 const points=values.map((v,i)=>`${pad+(i*Math.max(1,w-pad*2))/Math.max(1,values.length-1)},${h-pad-((v-min)*(h-pad*2))/Math.max(1,max-min)}`).join(' ');
 return data.length?<div className="line-wrap"><svg viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`${field} timeline`}><defs><linearGradient id={`g-${field}`} x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={color} stopOpacity=".25"/><stop offset="1" stopColor={color} stopOpacity="0"/></linearGradient></defs><polyline points={points} fill="none" stroke={color} strokeWidth="3" strokeLinejoin="round"/><polyline points={`${pad},${h-pad} ${points} ${w-pad},${h-pad}`} fill={`url(#g-${field})`} stroke="none"/></svg><div className="line-meta"><span>{data[0]?.bucket||'—'}</span><strong>{field.replaceAll('_',' ')} · peak {Math.round(max).toLocaleString()}</strong><span>{data.at(-1)?.bucket||'—'}</span></div></div>:<Empty/>;
}
export function ChartCard({title,subtitle,children,wide=false}){return <section className={`panel chart-card ${wide?'wide':''}`}><header><div><h3>{title}</h3><p>{subtitle}</p></div><span className="live-dot">LIVE</span></header>{children}</section>}
export function Empty(){return <div className="empty">Waiting for simulator data</div>}
