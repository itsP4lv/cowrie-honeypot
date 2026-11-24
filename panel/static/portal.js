"use strict";
/* Accueil (/) et page de statut (/status). Les textes sont insérés avec textContent. */
const $=s=>document.querySelector(s);
const NS="http://www.w3.org/2000/svg";
const nf=new Intl.NumberFormat("fr-FR");
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined&&text!==null)e.textContent=String(text);return e}
function svg(tag,attrs){const e=document.createElementNS(NS,tag);for(const k in attrs)e.setAttribute(k,attrs[k]);return e}
const ago=ts=>{const d=Date.now()-new Date(ts);if(!ts||isNaN(d))return"";const s=Math.round(d/1000);if(s<60)return"il y a "+s+" s";const m=Math.round(s/60);if(m<60)return"il y a "+m+" min";const h=Math.round(m/60);if(h<48)return"il y a "+h+" h";return"il y a "+Math.round(h/24)+" j"};
const STATE={up:["ok","En ligne"],slow:["warn","Lent"],down:["ko","Hors ligne"],pending:["wait","En attente"]};
function pill(state,text){const[c,l]=STATE[state]||STATE.pending;return el("span","pill "+c,text||l)}
function setPill(node,state,text){const[c,l]=STATE[state]||STATE.pending;node.className="pill "+c;node.textContent=text||l}

/* ---------- Thème (partagé avec le dashboard) ---------- */
const SUN='<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>';
const MOON='<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>';
function applyTheme(t){document.documentElement.dataset.theme=t;localStorage.setItem("theme",t);
 const s=svg("svg",{viewBox:"0 0 24 24",fill:"none",stroke:"currentColor","stroke-width":2,"stroke-linecap":"round","stroke-linejoin":"round"});s.innerHTML=t==="light"?MOON:SUN;$("#theme").replaceChildren(s)}
applyTheme(localStorage.getItem("theme")||(matchMedia("(prefers-color-scheme: light)").matches?"light":"dark"));
$("#theme").onclick=()=>applyTheme(document.documentElement.dataset.theme==="light"?"dark":"light");

async function getJSON(url){const r=await fetch(url,{cache:"no-store"});if(!r.ok)throw new Error(r.status);return r.json()}

/* ---------- Accueil ---------- */
async function home(){
 try{
  const d=await getJSON("/api/home");
  const hp=d.honeypot,box=$("#hp-stats");
  if(hp){
   const fresh=hp.last&&Date.now()-new Date(hp.last)<3*3600e3;
   setPill($("#hp-state"),fresh?"up":"slow",fresh?"Actif":"Calme");
   box.replaceChildren(...[["Connexions 24 h",nf.format(hp.connexions_24h)],["IP 24 h",nf.format(hp.ips_24h)],["Total",nf.format(hp.connexions)],["Dernier événement",ago(hp.last)||"—"]]
    .map(([l,v])=>{const s=el("div","sstat");s.append(el("b","",v),el("span","",l));return s}));
   const up=hp.first?(Date.now()-new Date(hp.first))/1000:0;
   if(up>0){const j=Math.floor(up/86400),h=Math.floor(up%86400/3600);
    setPill($("#soc-state"),"up","En ligne depuis "+(j?j+" j "+h+" h":h+" h"));
    $("#soc-stats").replaceChildren(...[["Connexions",nf.format(hp.connexions)],["IP uniques",nf.format(hp.ips)],["Par heure","≈ "+nf.format(Math.round(hp.connexions/(up/3600)))]]
     .map(([l,v])=>{const s=el("div","sstat");s.append(el("b","",v),el("span","",l));return s}))}
  }else{setPill($("#hp-state"),"pending","Import…");setPill($("#soc-state"),"pending","Import…")}
  const st=d.status;
  if(st.down)setPill($("#st-state"),"down",st.down+" hors ligne");
  else if(st.slow)setPill($("#st-state"),"slow",st.slow+" lent"+(st.slow>1?"s":""));
  else if(st.pending===st.total)setPill($("#st-state"),"pending");
  else setPill($("#st-state"),"up",st.up+"/"+st.total+" en ligne");
  $("#st-dots").replaceChildren(...st.targets.map(t=>{const s=el("span","sdot "+(STATE[t.state]||STATE.pending)[0]);s.append(el("i"),el("span","",t.name));return s}));
 }catch(e){setPill($("#hp-state"),"pending","?");setPill($("#st-state"),"pending","?")}
}

/* ---------- Page de statut ---------- */
function sparkline(vals){
 const W=160,H=36,v=vals.filter(x=>x!=null);const s=svg("svg",{viewBox:`0 0 ${W} ${H}`,class:"spark",preserveAspectRatio:"none"});
 if(v.length<2)return s;const max=Math.max(...v,1),step=W/(vals.length-1);let d="";
 vals.forEach((x,i)=>{if(x==null)return;d+=(d?"L":"M")+(i*step).toFixed(1)+","+(H-2-(H-4)*x/max).toFixed(1)});
 s.append(svg("path",{d,fill:"none",stroke:"var(--info)","stroke-width":1.6,"stroke-linejoin":"round","vector-effect":"non-scaling-stroke"}));return s}

function targetCard(t){
 const c=el("article","card st-item "+(STATE[t.state]||STATE.pending)[0]);
 const head=el("div","st-head"),title=el("div","st-title");
 title.append(el("b","",t.name));
 const sub=el("span","muted st-host",t.host+(t.kind==="tcp"?" · TCP":""));title.append(sub);
 head.append(title,pill(t.state));
 if(t.link){const a=el("a","btn st-open","Ouvrir");a.href=t.link;a.target="_blank";a.rel="noopener noreferrer";head.append(a)}
 const meta=el("div","st-meta");
 const m=(l,v,cls)=>{const s=el("div","sstat"+(cls?" "+cls:""));s.append(el("b","",v),el("span","",l));return s};
 meta.append(m("Temps de réponse",t.ms!=null?nf.format(t.ms)+" ms":"—"),
  m("Disponibilité 24 h",t.uptime!=null?t.uptime.toLocaleString("fr-FR",{maximumFractionDigits:2})+" %":"—"));
 if(t.code!=null)meta.append(m("Code HTTP",t.code));
 if(t.cert_days!=null)meta.append(m("Certificat TLS",t.cert_days<0?"expiré":"expire dans "+t.cert_days+" j",t.cert_days<14?"bad":""));
 meta.append(m("Vérifié",ago(t.checked)||"—"));
 const spark=el("div","st-spark");spark.append(sparkline(t.latency),el("span","muted","latence, dernière heure"));meta.append(spark);
 const bars=el("div","st-bars");
 const size=24*60/t.bars.length;
 t.bars.forEach((b,i)=>{const s=el("i",b?(STATE[b]||STATE.pending)[0]:"none");
  const from=new Date(Date.now()-(t.bars.length-i)*size*6e4);
  s.title=from.toLocaleTimeString("fr-FR",{hour:"2-digit",minute:"2-digit"})+" : "+(b?(STATE[b]||STATE.pending)[1]:"pas de données");bars.append(s)});
 const scale=el("div","st-scale");scale.append(el("span","","il y a 24 h"),el("span","","maintenant"));
 c.append(head);if(t.error)c.append(el("div","st-err",t.error));c.append(meta,bars,scale);return c}

async function statusPage(){
 try{
  const d=await getJSON("/api/status"),ts=d.targets;
  const live=$("#status");live.className="status";$("#live").textContent="à jour · "+new Date().toLocaleTimeString("fr-FR");
  const down=ts.filter(t=>t.state==="down"),slow=ts.filter(t=>t.state==="slow"),pend=ts.filter(t=>t.state==="pending");
  const b=$("#banner");b.className="card st-banner "+(down.length?"ko":slow.length?"warn":pend.length===ts.length?"wait":"ok");
  const msg=down.length?down.length+" service"+(down.length>1?"s":"")+" hors ligne : "+down.map(t=>t.name).join(", ")
   :slow.length?"Tout répond, mais "+slow.map(t=>t.name).join(", ")+(slow.length>1?" sont lents":" est lent")
   :pend.length===ts.length?"Première vérification en cours…":"Tous les services fonctionnent normalement";
  b.replaceChildren(el("i"),el("b","",msg),el("span","muted",ts.length+" service"+(ts.length>1?"s":"")+" surveillé"+(ts.length>1?"s":"")));
  $("#targets").replaceChildren(...ts.map(targetCard));
 }catch(e){$("#status").className="status err";$("#live").textContent="hors connexion"}
}

const page=document.body.dataset.page;
const run=page==="status"?statusPage:home;
run();setInterval(()=>{if(!document.hidden)run()},page==="status"?15000:30000);
