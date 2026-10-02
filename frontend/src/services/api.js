const API_KEY=import.meta.env.VITE_API_KEY || 'dev-analyst-key';
async function call(path, options={}) {
  const response=await fetch(path,{...options,headers:{'Content-Type':'application/json','X-API-Key':API_KEY,'X-Role':'analyst',...(options.headers||{})}});
  const data=await response.json().catch(()=>({detail:'Invalid server response'}));
  if(!response.ok) throw new Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail));
  return data;
}
export const api={get:(p)=>call(p),post:(p,b)=>call(p,{method:'POST',body:JSON.stringify(b)}),put:(p,b)=>call(p,{method:'PUT',body:JSON.stringify(b)})};
