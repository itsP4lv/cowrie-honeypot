"use strict";
/* Rappel : tout ce qui vient des logs est inséré avec textContent uniquement. */
const $=s=>document.querySelector(s);
const NS="http://www.w3.org/2000/svg";
const REFRESH_MS=5000;

const ICONS={ /* icônes fixes (pas de données attaquant) */
 activity:'<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
 globe:'<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/>',
 key:'<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
 unlock:'<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
 terminal:'<path d="m4 17 6-6-6-6M12 19h8"/>',
 file:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
 pause:'<rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/>',
 play:'<path d="M6 4l14 8-14 8z"/>',
 sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
 moon:'<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
 inbox:'<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.5 5.1 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.5-6.9A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.7 1.1z"/>',
 flag:'<path d="M4 22V4a1 1 0 0 1 .4-.8A6 6 0 0 1 8 2c3 0 5 2 8 2a6 6 0 0 0 4-1.5V14a6 6 0 0 1-4 1.5c-3 0-5-2-8-2a6 6 0 0 0-4 1.5"/>',
 x:'<path d="M18 6 6 18M6 6l12 12"/>',
 copy:'<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
 filter:'<path d="M22 3H2l8 9.5V19l4 2v-8.5z"/>',
 ext:'<path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
 ban:'<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>',
 replay:'<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/><path d="m10 9 5 3-5 3z"/>',
 bell:'<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.9 1.9 0 0 0 3.4 0"/>',
};
function icon(name){const s=document.createElementNS(NS,"svg");s.setAttribute("viewBox","0 0 24 24");s.setAttribute("fill","none");s.setAttribute("stroke","currentColor");
 s.setAttribute("stroke-width","2");s.setAttribute("stroke-linecap","round");s.setAttribute("stroke-linejoin","round");s.innerHTML=ICONS[name];return s}
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined&&text!==null)e.textContent=String(text);return e}
function svg(tag,attrs){const e=document.createElementNS(NS,tag);for(const k in attrs)e.setAttribute(k,attrs[k]);return e}
function emptyBox(msg){const d=el("div","empty");d.append(icon("inbox"),el("span","",msg||"Rien pour l'instant"));return d}
const nf=new Intl.NumberFormat("fr-FR");
const fmtTime=ts=>{const d=new Date(ts);return isNaN(d)?(ts||""):d.toLocaleString("fr-FR",{day:"2-digit",month:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"})};
const fmtHour=ts=>{const d=new Date(ts);return isNaN(d)?"":String(d.getHours()).padStart(2,"0")+"h"};
let toastT;function toast(msg){const t=$("#toast");t.textContent=msg;t.classList.add("show");clearTimeout(toastT);toastT=setTimeout(()=>t.classList.remove("show"),1800)}
function copy(text){if(!text)return;(navigator.clipboard?navigator.clipboard.writeText(text):Promise.reject()).then(()=>toast("Copié : "+text),()=>toast(text))}

/* ---------- Drapeaux / pays ---------- */
const CC_RE=/^[a-z]{2}$/;
const regionName=(()=>{try{const dn=new Intl.DisplayNames(["fr"],{type:"region"});return cc=>{try{return dn.of(cc.toUpperCase())}catch(e){return cc.toUpperCase()}}}catch(e){return cc=>cc.toUpperCase()}})();
function flag(cc,cls){if(!cc||!CC_RE.test(cc))return el("span","flag none"+(cls?" "+cls:""));
 const i=el("img","flag"+(cls?" "+cls:""));i.src="/flags/"+cc+".svg";i.alt=cc.toUpperCase();i.title=regionName(cc);i.loading="lazy";i.decoding="async";return i}
const countryOf=r=>r.private?"Réseau local":(r.country||(r.cc?regionName(r.cc):"Inconnu"));
const placeOf=r=>r.private?"Réseau local":[r.city,r.region,countryOf(r)].filter((v,i,a)=>v&&a.indexOf(v)===i).join(", ");
function ipTag(ip,cc){const s=el("span","iptag");s.append(flag(cc),el("span","",ip));return s}
const fmtDur=s=>{if(s==null||isNaN(s))return"";s=Math.round(s);if(s<60)return s+" s";if(s<3600)return Math.floor(s/60)+" min "+(s%60)+" s";return Math.floor(s/3600)+" h "+Math.floor(s%3600/60)+" min"};
const ago=ts=>{const d=Date.now()-new Date(ts);if(isNaN(d))return"";const m=Math.round(d/6e4);if(m<1)return"à l'instant";if(m<60)return"il y a "+m+" min";const h=Math.round(m/60);if(h<48)return"il y a "+h+" h";return"il y a "+Math.round(h/24)+" j"};

/* ---------- Thème ---------- */
function applyTheme(t){document.documentElement.dataset.theme=t;$("#theme").replaceChildren(icon(t==="light"?"moon":"sun"));localStorage.setItem("theme",t)}
applyTheme(localStorage.getItem("theme")||(matchMedia("(prefers-color-scheme: light)").matches?"light":"dark"));
$("#theme").onclick=()=>{applyTheme(document.documentElement.dataset.theme==="light"?"dark":"light");if(last)drawChart(last.per_hour)};

/* ---------- KPI ---------- */
const KPIS=[
 ["connexions","Connexions","activity","var(--acc)"],
 ["ips_uniques","IP uniques","globe","var(--info)"],
 ["pays","Pays d'origine","flag","var(--ok)"],
 ["tentatives","Tentatives de login","key","var(--vio)"],
 ["reussies","Logins réussis","unlock","var(--ko)"],
 ["commandes","Commandes tapées","terminal","var(--acc2)"],
 ["fichiers","Fichiers capturés","file","#e879f9"],
];
const kpiNodes={};
$("#kpis").replaceChildren(...KPIS.map(([k,label,ic,c])=>{
 const card=el("div","card kpi");card.style.setProperty("--c",c);
 const top=el("div","kpi-top"),chip=el("div","ic"),delta=el("span","delta");chip.append(icon(ic));top.append(chip,delta);
 const val=el("div","val");val.append(el("div","skel"));val.firstChild.style.width="60%";val.firstChild.style.height="28px";
 card.append(top,val,el("div","lbl",label));kpiNodes[k]={val,delta,cur:null};return card}));
function countUp(node,from,to){const t0=performance.now(),d=700;
 (function step(t){const p=Math.min(1,(t-t0)/d),e=1-Math.pow(1-p,3);node.textContent=nf.format(Math.round(from+(to-from)*e));if(p<1)requestAnimationFrame(step)})(t0)}
function updateKpis(totals){
 for(const [k] of KPIS){const n=kpiNodes[k],v=totals[k]||0;
  if(n.cur===null){countUp(n.val,0,v)}
  else if(v!==n.cur){countUp(n.val,n.cur,v);if(v>n.cur){n.delta.textContent="+"+nf.format(v-n.cur);n.delta.classList.add("show");clearTimeout(n.dt);n.dt=setTimeout(()=>n.delta.classList.remove("show"),4000)}}
  n.cur=v}}

/* ---------- Graphique 24 h ---------- */
function niceMax(v){if(v<=4)return 4;const p=Math.pow(10,Math.floor(Math.log10(v))),m=v/p;return (m<=1?1:m<=2?2:m<=5?5:10)*p}
function drawChart(rows){
 const box=$("#chart"),W=Math.max(320,box.clientWidth),H=box.clientHeight||240,P={l:34,r:8,t:10,b:24};
 const iw=W-P.l-P.r,ih=H-P.t-P.b,max=niceMax(Math.max(1,...rows.map(r=>Math.max(r.connexions,r.tentatives))));
 const x=i=>P.l+i*iw/Math.max(1,rows.length-1),y=v=>P.t+ih*(1-v/max);
 const s=svg("svg",{viewBox:`0 0 ${W} ${H}`,width:W,height:H});
 const defs=svg("defs",{});
 [["ga","var(--acc)"],["gv","var(--vio)"]].forEach(([id,c])=>{const g=svg("linearGradient",{id,x1:0,y1:0,x2:0,y2:1});
  g.append(svg("stop",{offset:"0%","stop-color":c,"stop-opacity":.35}),svg("stop",{offset:"100%","stop-color":c,"stop-opacity":0}));defs.append(g)});
 s.append(defs);
 for(let i=0;i<=4;i++){const v=max*i/4,yy=y(v);s.append(svg("line",{class:"gl",x1:P.l,x2:W-P.r,y1:yy,y2:yy}));
  const t=svg("text",{class:"ax",x:P.l-8,y:yy+3.5,"text-anchor":"end"});t.textContent=nf.format(v);s.append(t)}
 rows.forEach((r,i)=>{if(i%3===0||i===rows.length-1){const t=svg("text",{class:"ax",x:x(i),y:H-6,"text-anchor":"middle"});t.textContent=fmtHour(r.ts);s.append(t)}});
 const smooth=pts=>pts.map((p,i)=>{if(!i)return`M${p[0]},${p[1]}`;const q=pts[i-1],cx=(q[0]+p[0])/2;return`C${cx},${q[1]} ${cx},${p[1]} ${p[0]},${p[1]}`}).join("");
 [["tentatives","var(--vio)","gv"],["connexions","var(--acc)","ga"]].forEach(([k,c,g])=>{
  const pts=rows.map((r,i)=>[x(i),y(r[k])]),line=smooth(pts);
  s.append(svg("path",{d:`${line}L${x(rows.length-1)},${y(0)}L${x(0)},${y(0)}Z`,fill:`url(#${g})`}));
  s.append(svg("path",{d:line,fill:"none",stroke:c,"stroke-width":2.2,"stroke-linejoin":"round"}))});
 const cur=svg("line",{class:"cursor",y1:P.t,y2:H-P.b,x1:0,x2:0});
 const da=svg("circle",{class:"dot",r:4,fill:"var(--acc)",stroke:"var(--bg)","stroke-width":2}),dv=svg("circle",{class:"dot",r:4,fill:"var(--vio)",stroke:"var(--bg)","stroke-width":2});
 s.append(cur,dv,da);
 const tip=el("div","tip"),tb=el("b"),l1=el("div"),l2=el("div"),e1=el("em"),e2=el("em");
 const i1=el("i");i1.style.setProperty("--c","var(--acc)");const i2=el("i");i2.style.setProperty("--c","var(--vio)");
 l1.append(i1,"Connexions",e1);l2.append(i2,"Tentatives",e2);tip.append(tb,l1,l2);
 function at(i){const r=rows[i],xx=x(i);cur.setAttribute("x1",xx);cur.setAttribute("x2",xx);
  da.setAttribute("cx",xx);da.setAttribute("cy",y(r.connexions));dv.setAttribute("cx",xx);dv.setAttribute("cy",y(r.tentatives));
  const d=new Date(r.ts),f=new Date(d.getTime()+3600e3);tb.textContent=fmtHour(r.ts)+" – "+fmtHour(f.toISOString());
  e1.textContent=nf.format(r.connexions);e2.textContent=nf.format(r.tentatives);
  tip.style.left=Math.min(W-70,Math.max(70,xx))+"px";tip.style.top=Math.min(y(Math.max(r.connexions,r.tentatives)),ih)+"px"}
 s.addEventListener("mousemove",ev=>{const b=s.getBoundingClientRect(),px=(ev.clientX-b.left)*W/b.width;
  at(Math.max(0,Math.min(rows.length-1,Math.round((px-P.l)/iw*(rows.length-1)))))});
 at(rows.length-1);
 box.replaceChildren(s,tip);
 const tot=rows.reduce((a,r)=>a+r.connexions,0);
 $("#hours-total").textContent=nf.format(tot)+" connexion"+(tot>1?"s":"")+" · "+nf.format(rows.reduce((a,r)=>a+r.tentatives,0))+" tentatives";
}
let rT;addEventListener("resize",()=>{clearTimeout(rT);rT=setTimeout(()=>last&&drawChart(last.per_hour),120)});

/* ---------- Donut ---------- */
const R=70,C=2*Math.PI*R;
const dn={};(function(){const box=$("#donut"),ring=el("div","ring"),s=svg("svg",{viewBox:"0 0 170 170",width:170,height:170});
 s.append(svg("circle",{cx:85,cy:85,r:R,stroke:"var(--line)"}));dn.fg=svg("circle",{cx:85,cy:85,r:R,stroke:"var(--ok)","stroke-dasharray":`0 ${C}`});s.append(dn.fg);
 const c=el("div","center");dn.pct=el("b","","—");c.append(dn.pct,el("small","","de réussite"));ring.append(s,c);
 const split=el("div","split");const mk=(lbl,col)=>{const d=el("div"),sm=el("small"),i=el("i");i.style.setProperty("--c",col);sm.append(i,lbl);const b=el("b","","0");d.append(sm,b);split.append(d);return b};
 dn.ok=mk("Acceptés","var(--ok)");dn.ko=mk("Refusés","var(--ko)");box.append(ring,split)})();
function updateDonut(ok,total){const ko=total-ok,p=total?ok/total:0;
 dn.fg.setAttribute("stroke-dasharray",`${total?Math.max(.5,C*p):0} ${C}`);dn.pct.textContent=total?(p*100).toFixed(p<.1?1:0)+" %":"—";
 dn.ok.textContent=nf.format(ok);dn.ko.textContent=nf.format(ko)}

/* ---------- Classements ---------- */
const RANKS=[["top_ips","Top IP attaquantes","cliquer pour voir la fiche",true],["top_combos","Top combinaisons","identifiant / mot de passe"],
 ["top_users","Top identifiants",""],["top_passwords","Top mots de passe",""],["top_commands","Commandes les plus tapées",""],["top_clients","Clients SSH","version annoncée par l'attaquant"]];
const rankBoxes={};
$("#ranks").replaceChildren(...RANKS.map(([k,title,sub])=>{const c=el("div","card"),h=el("div","card-h"),h2=el("h2","",title);
 if(sub)h2.append(el("small","",sub));h.append(h2);const b=el("div","rank");for(let i=0;i<4;i++){const s=el("div","skel");s.style.margin="8px 0";b.append(s)}
 c.append(h,b);rankBoxes[k]=b;return c}));
function updateRank(k,rows,isIp){const box=rankBoxes[k];if(!rows.length)return box.replaceChildren(emptyBox());
 const max=Math.max(...rows.map(r=>r.count));
 box.replaceChildren(...rows.map((r,i)=>{const row=el("div","rk"+(isIp?" ip":"")),lb=el("div","lb"),tr=el("div","tr"),fill=el("i");
  fill.style.width=(r.count/max*100)+"%";tr.append(fill);const label=r.label===""?"(vide)":r.label;
  const sp=el("span");if(isIp)sp.append(flag(r.cc));sp.append(label);lb.append(sp,tr);lb.title=label;
  row.append(el("span","n",i+1),lb,el("span","ct",nf.format(r.count)));if(isIp)row.onclick=()=>openIp(r.label);return row}))}

/* ---------- Pays ---------- */
function updateCountries(rows){const box=$("#countries");if(!rows.length)return box.replaceChildren(emptyBox(last&&!last.geo?"Base de géolocalisation absente":"Rien pour l'instant"));
 const max=Math.max(...rows.map(r=>r.ips));
 box.replaceChildren(...rows.map((r,i)=>{const row=el("div","rk ip"),lb=el("div","lb"),tr=el("div","tr"),fill=el("i");
  fill.style.width=(r.ips/max*100)+"%";tr.append(fill);const sp=el("span");sp.append(flag(r.cc),countryOf(r));lb.append(sp,tr);
  lb.title=nf.format(r.connexions)+" connexion"+(r.connexions>1?"s":"");
  row.append(el("span","n",i+1),lb,el("span","ct",nf.format(r.ips)+" IP"));
  row.onclick=()=>{$("#ipfilter").value=countryOf(r);renderIps();$("#iptable").closest(".card").scrollIntoView({behavior:"smooth",block:"start"})};return row}))}

/* ---------- Carte (projection équirectangulaire, contours Natural Earth en TopoJSON) ---------- */
const MAP={W:1000,top:84,bot:-58};MAP.H=MAP.W*(MAP.top-MAP.bot)/360;
const mx=lon=>(lon+180)/360*MAP.W,my=lat=>(MAP.top-lat)/360*MAP.W;
const map={};
function topoPath(t){const [sx,sy]=t.transform.scale,[tx,ty]=t.transform.translate;
 const arcs=t.arcs.map(a=>{let x=0,y=0;return a.map(([dx,dy])=>{x+=dx;y+=dy;return[mx(x*sx+tx),my(y*sy+ty)]})});
 const ring=r=>{const pts=[];r.forEach(i=>{const a=i<0?arcs[~i].slice().reverse():arcs[i];pts.push(...(pts.length?a.slice(1):a))});
  /* un saut de plus d'une demi-largeur = passage de l'antiméridien : on lève le crayon au lieu de tracer une ligne à travers la carte */
  return pts.map((p,i)=>(i&&Math.abs(p[0]-pts[i-1][0])<MAP.W/2?"L":"M")+p[0].toFixed(1)+","+p[1].toFixed(1)).join("")+"Z"};
 let d="";for(const g of Object.values(t.objects)[0].geometries){const polys=g.type==="Polygon"?[g.arcs]:g.type==="MultiPolygon"?g.arcs:[];for(const p of polys)for(const r of p)d+=ring(r)}
 return d}
(function initMap(){const box=$("#map");map.svg=svg("svg",{viewBox:`0 0 ${MAP.W} ${MAP.H.toFixed(1)}`});
 for(let lon=-150;lon<=150;lon+=30)map.svg.append(svg("line",{class:"grat",x1:mx(lon),x2:mx(lon),y1:0,y2:MAP.H}));
 for(let lat=-30;lat<=60;lat+=30)map.svg.append(svg("line",{class:"grat",x1:0,x2:MAP.W,y1:my(lat),y2:my(lat)}));
 const land=svg("path",{class:"land"});map.dots=svg("g",{});map.svg.append(land,map.dots);
 map.tip=el("div","tip maptip");map.empty=el("div","map-empty");box.replaceChildren(map.svg,map.tip,map.empty);
 fetch("/map/land.json").then(r=>r.ok?r.json():null).then(t=>{if(t)land.setAttribute("d",topoPath(t))}).catch(()=>{});
 box.addEventListener("mouseleave",()=>map.tip.classList.remove("on"))})();
function mapTip(g,ev){const b=$("#map").getBoundingClientRect(),t=map.tip;
 const h=el("b");h.append(flag(g.cc),placeOf(g));
 const l1=el("div"),e1=el("em",""),l2=el("div"),e2=el("em","");
 l1.append("Adresses IP",e1);e1.textContent=nf.format(g.ips.length);l2.append("Connexions",e2);e2.textContent=nf.format(g.conn);
 const list=el("span","ips",g.ips.slice(0,4).map(r=>r.ip).join("  ")+(g.ips.length>4?"  +"+(g.ips.length-4):""));
 t.replaceChildren(h,l1,l2,list);t.style.left=Math.min(b.width-110,Math.max(110,ev.clientX-b.left))+"px";t.style.top=(ev.clientY-b.top)+"px";t.classList.toggle("below",ev.clientY-b.top<b.height/2);t.classList.add("on")}
function updateMap(ips){
 const groups=new Map();
 for(const r of ips){if(r.lat==null||r.lon==null)continue;const k=r.lat.toFixed(1)+","+r.lon.toFixed(1);let g=groups.get(k);
  if(!g){g={lat:r.lat,lon:r.lon,cc:r.cc,city:r.city,region:r.region,country:r.country,ips:[],conn:0,ok:0,last:""};groups.set(k,g)}
  g.ips.push(r);g.conn+=r.connexions;g.ok+=r.reussies;if(r.last>g.last)g.last=r.last}
 const list=[...groups.values()].sort((a,b)=>b.conn-a.conn);
 const sig=list.map(g=>g.lat+g.lon+":"+g.conn+":"+g.ok+":"+g.ips.length).join("|")+Math.floor(Date.now()/6e4);
 const geoN=ips.filter(r=>r.lat!=null).length;
 $("#map-sub").textContent=nf.format(list.length)+" emplacement"+(list.length>1?"s":"")+" · "+nf.format(geoN)+" IP géolocalisée"+(geoN>1?"s":"");
 map.empty.textContent=last&&!last.geo?"Base de géolocalisation absente (voir README)":list.length?"":"Aucune IP géolocalisée pour l'instant";
 if(sig===map.sig)return;map.sig=sig;
 const max=Math.max(1,...list.map(g=>g.conn)),now=Date.now();
 map.dots.replaceChildren(...list.map(g=>{const p=svg("g",{class:"pt"+(g.ok?" ok":"")}),x=mx(g.lon),y=my(g.lat),r=3.5+10*Math.sqrt(g.conn/max);
  if(now-new Date(g.last)<15*6e4)p.append(svg("circle",{class:"p",cx:x,cy:y,r}));
  p.append(svg("circle",{class:"c",cx:x,cy:y,r}));
  p.addEventListener("mousemove",ev=>mapTip(g,ev));
  p.addEventListener("click",()=>{if(g.ips.length===1)return openIp(g.ips[0].ip);$("#ipfilter").value=g.city||countryOf(g);renderIps();
   $("#iptable").closest(".card").scrollIntoView({behavior:"smooth",block:"start"})});
  return p}))}

/* ---------- Tableau des IP ---------- */
const IPCOLS=[["pays","Origine",""],["ip","IP",""],["org","Réseau (AS)",""],["tags","Comportements",""],["connexions","Connexions","num"],["tentatives","Tentatives","num"],
 ["reussies","Réussis","num"],["commandes","Commandes","num"],["last","Dernière activité",""]];
let ipSort={k:"last",dir:-1};const IP_ROWS=300;
const ipKey=(r,k)=>k==="tags"?(r.tags||[]).length:k==="pays"?countryOf(r)+" "+(r.city||""):k==="org"?(r.org||""):k==="ip"?r.ip.split(/[.:]/).map(p=>p.padStart(5,"0")).join("."):r[k];
function renderIps(){if(!last)return;const q=$("#ipfilter").value.trim().toLowerCase(),all=last.ips||[];
 let rows=q?all.filter(r=>[r.ip,countryOf(r),r.city,r.region,r.org,r.asn?"as"+r.asn:"",...(r.tags||[]).map(t=>TAG_LABELS[t]||t)].some(v=>v&&String(v).toLowerCase().includes(q))):all.slice();
 rows.sort((a,b)=>{const x=ipKey(a,ipSort.k),y=ipKey(b,ipSort.k);return(x>y?1:x<y?-1:0)*ipSort.dir});
 const thead=el("thead"),hr=el("tr");
 IPCOLS.forEach(([k,h,c])=>{const th=el("th","sort "+c+(ipSort.k===k?" on"+(ipSort.dir>0?" asc":""):""),h);
  th.onclick=()=>{ipSort=ipSort.k===k?{k,dir:-ipSort.dir}:{k,dir:k==="pays"||k==="ip"||k==="org"?1:-1};renderIps()};hr.append(th)});thead.append(hr);
 const tb=el("tbody");
 if(!rows.length){const tr=el("tr"),td=el("td");td.colSpan=IPCOLS.length;td.append(emptyBox(q?"Aucune IP pour ce filtre":"Rien pour l'instant"));tr.append(td);tb.append(tr)}
 rows.slice(0,IP_ROWS).forEach(r=>{const tr=el("tr");tr.onclick=()=>openIp(r.ip);
  const loc=el("td","loc"),top=el("span","iptag");top.append(flag(r.cc),countryOf(r));loc.append(top);if(r.city)loc.append(el("small","",r.city));
  const org=el("td","org",r.asn?"AS"+r.asn+(r.org?" · "+r.org:""):(r.org||"—"));org.title=org.textContent;
  const num=(v,ok)=>{const td=el("td","num"+(v?"":" zero"));if(ok&&v)td.append(el("span","pill ko",nf.format(v)));else td.textContent=nf.format(v);return td};
  const lt=el("td","t",ago(r.last));lt.title=fmtTime(r.last);
  const ipc=el("td","mono",r.ip);if(banOf(r.ip))ipc.append(el("span","pill ban","Bannie"));
  const tg=el("td","tg");tg.append(tagList((r.tags||[]).map(t=>({tag:t,label:TAG_LABELS[t]||t})),3));
  tr.append(loc,ipc,org,tg,num(r.connexions),num(r.tentatives),num(r.reussies,true),num(r.commandes),lt);tb.append(tr)});
 $("#iptable").replaceChildren(thead,tb);
 const tot=last.ips_total||all.length;
 $("#ip-sub").textContent=(q?nf.format(rows.length)+" sur ":"")+nf.format(tot)+" IP"+(rows.length>IP_ROWS?" · "+IP_ROWS+" affichées":"")+" · cliquer sur une ligne pour voir la fiche"}
$("#ipfilter").addEventListener("input",renderIps);

/* ---------- Bans ---------- */
const BAN_STATUS={actif:["pill ban","Bloquée"],attente:["pill wait","En attente"],refuse:["pill off","Refusée"]};
const banOf=ip=>last&&last.bans?last.bans.list.find(b=>b.ip===ip):null;
async function banApi(method,path,body){
 const r=await fetch(path,{method,headers:{"Content-Type":"application/json","X-Panel":"1"},body:JSON.stringify(body||{})});
 if(!r.ok){let m="erreur "+r.status;try{const t=await r.text();const x=/<p>(.*?)<\/p>/.exec(t);if(x)m=x[1]}catch(e){}throw new Error(m)}
 return r.json()}
async function setBan(ip,on,btnEl){
 if(on&&!confirm("Bannir "+ip+" ?\n\nL'IP sera bloquée au pare-feu du VPS : elle ne pourra plus joindre le honeypot ni le vrai SSH."))return;
 if(btnEl)btnEl.disabled=true;
 try{const bans=await banApi(on?"POST":"DELETE",on?"/api/bans":"/api/bans/"+encodeURIComponent(ip),on?{ip,reason:"ban manuel depuis le panel"}:null);
  if(last)last.bans=bans;toast(on?"IP bannie : "+ip:"IP débannie : "+ip);renderBans();renderIps();if(curIp===ip)loadIp()}
 catch(e){toast("Impossible : "+e.message)}finally{if(btnEl)btnEl.disabled=false}}
function banButton(ip,isPrivate){if(isPrivate)return el("span");const b=banOf(ip);
 const x=el("button",b?"btn":"btn danger");x.type="button";x.append(icon("ban"),b?"Débannir":"Bannir l'IP");x.onclick=()=>setBan(ip,!b,x);return x}
function banBox(ip){const b=banOf(ip);if(!b)return null;const [cls,lbl]=BAN_STATUS[b.status]||BAN_STATUS.attente;
 const box=el("div","banbox"+(b.status==="actif"?"":" wait"));box.append(el("span",cls,lbl));
 box.append(el("span","",b.status==="actif"?"Bannie le "+fmtTime(b.ts)+", bloquée au pare-feu.":b.status==="refuse"?"Le pare-feu a refusé ce ban : "+b.detail:"Bannie le "+fmtTime(b.ts)+", en attente d'application par le service du VPS."));
 return box}
function renderBans(){if(!last)return;const B=last.bans||{list:[]},rows=B.list,t=$("#bantable"),w=$("#ban-warn");
 w.replaceChildren();
 if(B.helper_error)w.append(el("p","warn","Erreur du service de ban : "+B.helper_error));
 else if(B.helper_late)w.append(el("p","warn","Le service de ban du VPS ne semble pas tourner : les IP sont dans la liste mais pas encore bloquées (voir host/ dans le README)."));
 $("#ban-sub").textContent=rows.length?nf.format(rows.filter(r=>r.status==="actif").length)+" bloquée"+(rows.length>1?"s":"")+" sur "+nf.format(rows.length)+" · au pare-feu du VPS (honeypot et vrai SSH)":"bloquées au pare-feu du VPS (honeypot et vrai SSH)";
 const thead=el("thead"),hr=el("tr");["IP","Pays","Bannie le","Statut",""].forEach(h=>hr.append(el("th","",h)));thead.append(hr);
 const tb=el("tbody");
 if(!rows.length){const tr=el("tr"),td=el("td");td.colSpan=5;td.append(emptyBox("Aucune IP bannie. Ouvre la fiche d'une IP et clique sur « Bannir l'IP »."));tr.append(td);tb.append(tr)}
 rows.forEach(b=>{const tr=el("tr"),ipc=el("td","ip");ipc.append(ipTag(b.ip,b.cc));ipc.onclick=()=>openIp(b.ip);
  const [cls,lbl]=BAN_STATUS[b.status]||BAN_STATUS.attente,st=el("td");st.append(el("span",cls,lbl));if(b.detail)st.title=b.detail;
  const ac=el("td");ac.style.textAlign="right";const x=el("button","btn");x.type="button";x.append(icon("x"),"Débannir");x.onclick=()=>setBan(b.ip,false,x);ac.append(x);
  tr.append(ipc,el("td","",b.country||(b.cc?regionName(b.cc):"—")),el("td","t",fmtTime(b.ts)),st,ac);tb.append(tr)});
 t.replaceChildren(thead,tb)}

/* ---------- Comportements ---------- */
let TAG_LABELS={};
function tagList(list,max){const box=el("div","tags");(max?list.slice(0,max):list).forEach(t=>box.append(el("span","tag "+(/^[a-z]+$/.test(t.tag)?t.tag:""),t.label)));
 if(max&&list.length>max)box.append(el("span","tag","+"+(list.length-max)));return box}
function updateBehaviours(rows){rows.forEach(r=>TAG_LABELS[r.tag]=r.label);const box=$("#behaviours");
 if(!rows.length)return box.replaceChildren(emptyBox("Aucune commande classée pour l'instant"));
 const max=Math.max(...rows.map(r=>r.ips));
 box.replaceChildren(...rows.map((r,i)=>{const row=el("div","rk ip"),lb=el("div","lb"),tr=el("div","tr"),fill=el("i");
  fill.style.width=(r.ips/max*100)+"%";tr.append(fill);const sp=el("span");sp.append(el("span","tag "+(/^[a-z]+$/.test(r.tag)?r.tag:""),r.label));lb.append(sp,tr);
  lb.title=nf.format(r.sessions)+" session"+(r.sessions>1?"s":"");
  row.append(el("span","n",i+1),lb,el("span","ct",nf.format(r.ips)+" IP"));
  row.onclick=()=>{$("#ipfilter").value=r.label;renderIps();$("#iptable").closest(".card").scrollIntoView({behavior:"smooth",block:"start"})};return row}))}

/* ---------- Carte de chaleur (7 jours × 24 h, heure locale) ---------- */
function updateHeat(rows){const box=$("#heat"),grid=Array.from({length:7},()=>new Array(24).fill(0));
 const today=new Date();today.setHours(0,0,0,0);
 rows.forEach(r=>{const d=new Date(r.ts);if(isNaN(d))return;const day=new Date(d);day.setHours(0,0,0,0);
  const ago=Math.round((today-day)/864e5);if(ago<0||ago>6)return;grid[6-ago][d.getHours()]+=r.n});
 const max=Math.max(1,...grid.flat()),days=["dim.","lun.","mar.","mer.","jeu.","ven.","sam."],nodes=[el("span")];
 for(let h=0;h<24;h++)nodes.push(el("span","hh",h%3===0?String(h).padStart(2,"0"):""));
 grid.forEach((row,i)=>{const day=new Date(today.getTime()-(6-i)*864e5);nodes.push(el("span","d",i===6?"auj.":days[day.getDay()]));
  row.forEach((n,h)=>{const c=el("span","c");if(n){c.dataset.n=n;c.style.setProperty("--p",Math.round(15+85*n/max)+"%")}
   c.title=day.toLocaleDateString("fr-FR",{weekday:"long",day:"numeric",month:"long"})+" · "+String(h).padStart(2,"0")+"h : "+nf.format(n)+" connexion"+(n>1?"s":"");nodes.push(c)})});
 box.replaceChildren(...nodes)}

/* ---------- VirusTotal ---------- */
function vtCell(v){if(!last||!last.features||!last.features.virustotal)return["—","pill vt-none"];
 if(!v)return["en attente","pill vt-none"];if(v.status==="inconnu")return["inconnu de VT","pill vt-none"];
 return[v.malicious+"/"+v.total+(v.label?" · "+v.label:""),v.malicious>0?"pill vt-bad":"pill vt-ok"]}

/* ---------- Fonctions activées (pied de page) ---------- */
let featKey="";
function updateFeatures(f,sensors){const k=JSON.stringify([f,sensors]);if(k===featKey)return;featKey=k;const box=$("#features");
 const item=(label,on,txt)=>{const s=el("span","");s.append(label+" : ");s.append(el("b",on?"on":"",txt));return s};
 const al=f.alerts&&f.alerts.length;
 box.replaceChildren(item("Honeypots",true,sensors.join(", ")||"—"),item("Alertes",al,al?f.alerts.join(", "):"désactivées"),
  item("VirusTotal",f.virustotal,f.virustotal?"actif (hash uniquement)":"désactivé"));
 if(al){const b=el("button","btn sm");b.type="button";b.append(icon("bell"),"Tester les alertes");
  b.onclick=async()=>{b.disabled=true;try{await banApi("POST","/api/alerts/test",{});toast("Alerte de test envoyée")}catch(e){toast("Échec : "+e.message)}finally{b.disabled=false}};box.append(b)}}

/* ---------- Relecture d'une session (enregistrement d'écran de Cowrie) ---------- */
const RP={frames:[],i:0,timer:null,speed:1,showInput:false,playing:false};
const SPEEDS=[1,2,5,20];
function termRender(upto){/* mini terminal : texte brut uniquement, séquences ANSI retirées, \r et retour arrière gérés */
 const out=[];let line="",col=0,lines=[];
 const flush=()=>{if(lines.length||line){out.push([lines.length?lines.join("\n")+"\n"+line:line,false]);lines=[];line="";col=0}};
 const put=txt=>{
  txt=txt.replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]/g,"").replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g,"").replace(/\x1b[()][A-Za-z0-9]/g,"").replace(/\x1b./g,"");
  for(const ch of txt){if(ch==="\n"){lines.push(line);line="";col=0}else if(ch==="\r"){col=0}else if(ch==="\b"||ch==="\x7f"){col=Math.max(0,col-1)}
   else if(ch<" "&&ch!=="\t"){}else{line=line.slice(0,col)+ch+line.slice(col+1);col++}}};
 for(let k=0;k<upto;k++){const [,dir,txt]=RP.frames[k];
  if(dir===1){if(RP.showInput){flush();out.push(["› "+txt.replace(/\r/g,"").replace(/\n$/,"")+"\n",true])}}else put(txt)}
 flush();const pre=$("#rp-term");pre.replaceChildren(...out.map(([t,isIn])=>isIn?el("span","in",t):document.createTextNode(t)));pre.scrollTop=pre.scrollHeight}
function rpStep(){if(!RP.playing)return;if(RP.i>=RP.frames.length){rpPause();return}
 RP.i++;termRender(RP.i);const total=RP.frames[RP.frames.length-1][0],cur=RP.frames[RP.i-1][0];
 $("#rp-prog").style.width=(RP.i/RP.frames.length*100)+"%";$("#rp-time").textContent=fmtDur(cur/1000)+" / "+fmtDur(total/1000);
 const next=RP.frames[RP.i];if(!next){rpPause();return}
 RP.timer=setTimeout(rpStep,Math.min(1500,Math.max(0,next[0]-cur))/RP.speed)}
function rpPlay(){if(!RP.frames.length)return;if(RP.i>=RP.frames.length)RP.i=0;RP.playing=true;$("#rp-play").replaceChildren(icon("pause"),"Pause");rpStep()}
function rpPause(){RP.playing=false;clearTimeout(RP.timer);$("#rp-play").replaceChildren(icon("play"),RP.frames.length&&RP.i>=RP.frames.length?"Rejouer":"Lecture")}
async function openReplay(session,ip){const m=$("#replay");m.classList.add("open");m.setAttribute("aria-hidden","false");RP.frames=[];RP.i=0;rpPause();
 $("#rp-title").textContent="Session "+session.slice(0,8)+" · "+ip;$("#rp-term").textContent="Chargement…";$("#rp-time").textContent="";$("#rp-prog").style.width="0";
 try{const r=await fetch("/api/tty/"+encodeURIComponent(session),{cache:"no-store"});if(!r.ok)throw new Error(r.status);const d=await r.json();
  RP.frames=d.frames||[];RP.i=0;
  /* bot sans terminal (mode « exec ») : rien n'est renvoyé en écho, on montre donc les entrées par défaut */
  const len=dir=>RP.frames.filter(f=>f[1]===dir).reduce((a,f)=>a+f[2].length,0),inLen=len(1);
  RP.showInput=inLen>0&&len(2)<inLen*3;$("#rp-input").textContent="Entrées : "+(RP.showInput?"oui":"non");
  if(!RP.frames.length){$("#rp-term").textContent="Enregistrement vide.";return}
  if(d.truncated)toast("Enregistrement très long : relecture tronquée");rpPlay()}
 catch(e){$("#rp-term").textContent="Impossible de charger l'enregistrement ("+e.message+")."}}
function closeReplay(){rpPause();$("#replay").classList.remove("open");$("#replay").setAttribute("aria-hidden","true")}
$("#rp-play").onclick=()=>RP.playing?rpPause():rpPlay();
$("#rp-speed").onclick=()=>{RP.speed=SPEEDS[(SPEEDS.indexOf(RP.speed)+1)%SPEEDS.length];$("#rp-speed").textContent="×"+RP.speed};
$("#rp-input").onclick=()=>{RP.showInput=!RP.showInput;$("#rp-input").textContent="Entrées : "+(RP.showInput?"oui":"non");termRender(RP.i)};
$("#rp-close").replaceChildren(icon("x"));$("#rp-close").onclick=closeReplay;rpPause();
$("#replay").addEventListener("click",e=>{if(e.target.id==="replay")closeReplay()});
document.addEventListener("keydown",e=>{if(e.key==="Escape"&&$("#replay").classList.contains("open")){e.stopImmediatePropagation();closeReplay()}},true);
/* ---------- Fiche d'une IP ---------- */
let curIp=null;
const LINKS=[["AbuseIPDB","https://www.abuseipdb.com/check/"],["Shodan","https://www.shodan.io/host/"],["VirusTotal","https://www.virustotal.com/gui/ip-address/"],
 ["GreyNoise","https://viz.greynoise.io/ip/"],["Censys","https://search.censys.io/hosts/"],["ipinfo","https://ipinfo.io/"]];
function closeIp(){curIp=null;$("#drawer").classList.remove("open");$("#scrim").classList.remove("open");$("#drawer").setAttribute("aria-hidden","true")}
$("#scrim").onclick=closeIp;document.addEventListener("keydown",e=>{if(e.key==="Escape"&&curIp)closeIp()});
function openIp(ip){curIp=ip;const d=$("#drawer");d.classList.add("open");$("#scrim").classList.add("open");d.setAttribute("aria-hidden","false");
 const w=el("div","dw");for(let i=0;i<6;i++){const s=el("div","skel");s.style.height=i?"40px":"28px";w.append(s)}d.replaceChildren(w);d.scrollTop=0;loadIp()}
async function loadIp(){const ip=curIp;if(!ip)return;
 try{const r=await fetch("/api/ip/"+encodeURIComponent(ip),{cache:"no-store"});if(!r.ok)throw new Error(r.status);const d=await r.json();
  if(curIp===ip)renderIp(d)}catch(e){if(curIp===ip){const w=el("div","dw");w.append(emptyBox("Impossible de charger la fiche de "+ip));$("#drawer").replaceChildren(w)}}}
function btn(ic,label,fn){const b=el("button","btn");b.type="button";b.append(icon(ic),label);b.onclick=fn;return b}
function renderIp(d){const box=$("#drawer"),st=box.scrollTop,w=el("div","dw");
 /* en-tête */
 const h=el("div","dw-h"),t=el("div");t.append(el("h3","",d.ip),el("p","",placeOf(d)||"Localisation inconnue"));
 const x=el("button","btn icon");x.type="button";x.title="Fermer (Échap)";x.append(icon("x"));x.onclick=closeIp;h.append(flag(d.cc,"lg"),t,x);
 const act=el("div","dw-act");act.append(btn("copy","Copier l'IP",()=>copy(d.ip)),
  btn("filter","Filtrer le flux",()=>{$("#filter").value=d.ip;renderFeed(false);closeIp();$("#feed").closest(".card").scrollIntoView({behavior:"smooth"})}));
 /* chiffres */
 const mini=el("div","mini");[["connexions","Connexions"],["sessions","Sessions"],["tentatives","Tentatives"],["reussies","Logins réussis"],["commandes","Commandes"],["fichiers","Fichiers"]]
  .forEach(([k,l])=>{const c=el("div");c.append(el("b","",nf.format(d[k]||0)),el("small","",l));mini.append(c)});
 /* informations */
 const sec=(title,...nodes)=>{const s=el("section");s.append(el("h4","",title),...nodes);return s};
 const info=el("dl","info");const row=(k,v)=>{if(v===""||v==null)return;const dd=el("dd");if(v instanceof Node)dd.append(v);else dd.textContent=String(v);info.append(el("dt","",k),dd)};
 const cn=el("span","iptag");cn.append(flag(d.cc),countryOf(d)+(d.cc?" ("+d.cc.toUpperCase()+")":""));
 row("Pays",cn);row("Ville",d.city);row("Région",d.region);row("Continent",d.continent);
 row("ASN",d.asn?"AS"+d.asn:"");row("Organisation",d.org);
 row("Coordonnées",d.lat!=null?d.lat.toFixed(3)+", "+d.lon.toFixed(3)+" (approx.)":"");
 row("Première vue",fmtTime(d.first)+" · "+ago(d.first));row("Dernière vue",fmtTime(d.last)+" · "+ago(d.last));
 row("Clients SSH",(d.clients||[]).map(c=>c.label).join(", "));row("Type",d.private?"Adresse privée / locale":"Adresse publique");
 act.append(banButton(d.ip,d.private));
 w.append(h,act);if(d.tags&&d.tags.length)w.append(tagList(d.tags));const bb=banBox(d.ip);if(bb)w.append(bb);w.append(mini,sec("Informations",info));
 /* identifiants */
 if(d.credentials&&d.credentials.length){const tw=el("div","tw"),tb=el("table"),th=el("thead"),tr=el("tr");["Utilisateur","Mot de passe","Essais",""].forEach(x=>tr.append(el("th","",x)));th.append(tr);
  const body=el("tbody");d.credentials.forEach(c=>{const r=el("tr"),p=el("td");p.append(el("span",c.ok?"pill ok":"pill ko",c.ok?"Réussi":"Échec"));
   r.append(el("td","code",c.user===""?"(vide)":c.user),el("td","code",c.password===""?"(vide)":c.password),el("td","num",nf.format(c.count)),p);body.append(r)});
  tb.append(th,body);tw.append(tb);tw.style.maxHeight="260px";w.append(sec("Identifiants essayés",tw))}
 /* sessions */
 if(d.session_list&&d.session_list.length){const wrap=el("div");d.session_list.forEach(s=>{const c=el("div","sess"),hd=el("div","sess-h");
   hd.append(el("b","",fmtTime(s.start)));if(s.protocol)hd.append(el("span","",s.protocol.toUpperCase()+(s.port?" :"+s.port:"")));
   if(s.duration!=null)hd.append(el("span","","durée "+fmtDur(s.duration)));if(s.client)hd.append(el("span","",s.client));
   hd.append(el("span","",(s.id||"").slice(0,8)));if(s.sensor&&s.sensor!=="cowrie")hd.append(el("span","",s.sensor));
   if(s.tty){const rb=el("button","btn sm");rb.type="button";rb.append(icon("replay"),"Rejouer");rb.onclick=()=>openReplay(s.id,d.ip);rb.style.marginLeft="auto";hd.append(rb)}
   c.append(hd);if(s.tags&&s.tags.length){const t=tagList(s.tags);t.style.padding="8px 12px 0";c.append(t)}
   const b=el("div","sess-b");s.logins.forEach(l=>b.append(el("div","l"+(l.ok?" ok":""),(l.ok?"✔ login ":"✘ login ")+(l.user||"(vide)")+" / "+(l.password||"(vide)"))));
   s.commands.forEach(x=>b.append(el("div","c",x.input)));s.files.forEach(f=>b.append(el("div","l","↓ "+f.url)));
   if(!b.childNodes.length)b.append(el("div","l","Connexion sans authentification"));c.append(b);wrap.append(c)});
  w.append(sec("Sessions ("+nf.format(d.sessions)+")",wrap))}
 /* fichiers */
 if(d.files&&d.files.length){const tw=el("div","tw"),tb=el("table"),body=el("tbody");
  d.files.forEach(f=>{const r=el("tr"),hash=el("td","code");
   if(/^[a-f0-9]{64}$/i.test(f.sha256)){const a=el("a","",f.sha256);a.href="https://www.virustotal.com/gui/file/"+f.sha256;a.target="_blank";a.rel="noopener noreferrer";a.style.color="var(--info)";hash.append(a)}else hash.textContent=f.sha256||"—";
   const vtc=el("td");const [vt1,vt2]=vtCell(f.vt);vtc.append(el("span",vt2,vt1));r.append(el("td","t",fmtTime(f.ts)),el("td","code",f.url),hash,vtc);body.append(r)});tb.append(body);tw.append(tb);w.append(sec("Fichiers",tw))}
 /* liens externes (ouverts seulement sur clic) */
 if(!d.private){const l=el("div","links");LINKS.forEach(([n,u])=>{const a=el("a","btn");a.href=u+encodeURIComponent(d.ip);a.target="_blank";a.rel="noopener noreferrer";a.append(icon("ext"),n);l.append(a)});
  w.append(sec("Rechercher cette IP",l))}
 box.replaceChildren(w);box.scrollTop=st}

/* ---------- Flux d'événements ---------- */
const FEEDS={
 commands:{title:"Commandes",head:["Heure","IP","Session","Commande"],key:r=>r.ts+r.ip+r.input,
  cells:r=>[[fmtTime(r.ts),"t"],[r.ip,"ip",r.cc],[(r.session||"").slice(0,8),"sess"],[r.input,"code cmd"]]},
 logins:{title:"Connexions",head:["Heure","IP","Utilisateur","Mot de passe","Résultat"],key:r=>r.ts+r.ip+r.user+r.password,
  cells:r=>[[fmtTime(r.ts),"t"],[r.ip,"ip",r.cc],[r.user,"code"],[r.password,"code"],[r.ok?"Réussi":"Échec",r.ok?"pill ok":"pill ko"]]},
 files:{title:"Fichiers",head:["Heure","IP","URL / fichier","SHA-256","VirusTotal"],key:r=>r.ts+r.ip+r.url,
  cells:r=>[[fmtTime(r.ts),"t"],[r.ip,"ip",r.cc],[r.url,"code"],[r.sha256,"code"],vtCell(r.vt)]},
};
let tab=localStorage.getItem("tab")||"commands";if(!FEEDS[tab])tab="commands";
const seen={},tabCount={};
$("#tabs").replaceChildren(...Object.entries(FEEDS).map(([k,f])=>{const b=el("button","tab"+(k===tab?" on":""),f.title);b.dataset.k=k;tabCount[k]=el("em","","0");b.append(tabCount[k]);
 b.onclick=()=>{tab=k;localStorage.setItem("tab",k);document.querySelectorAll(".tab").forEach(t=>t.classList.toggle("on",t.dataset.k===k));renderFeed(false)};return b}));
$("#filter").addEventListener("input",()=>renderFeed(false));
function renderFeed(markNew){
 const f=FEEDS[tab],rows=last?last[tab]:[],q=$("#filter").value.trim().toLowerCase(),t=$("#feed");
 if(!last)return;
 if(!seen[tab]){seen[tab]=new Set(rows.map(f.key));markNew=false}
 const fresh=new Set(markNew?rows.map(f.key).filter(k=>!seen[tab].has(k)):[]);rows.forEach(r=>seen[tab].add(f.key(r)));
 const shown=q?rows.filter(r=>f.cells(r).some(([v])=>String(v).toLowerCase().includes(q))):rows;
 const thead=el("thead"),hr=el("tr");f.head.forEach(h=>hr.append(el("th","",h)));thead.append(hr);
 const tb=el("tbody");
 if(!shown.length){const tr=el("tr"),td=el("td");td.colSpan=f.head.length;td.append(emptyBox(q?"Aucun résultat pour ce filtre":"Rien pour l'instant"));tr.append(td);tb.append(tr)}
 shown.forEach(r=>{const tr=el("tr");if(fresh.has(f.key(r)))tr.className="new";
  f.cells(r).forEach(([v,c,cc])=>{let td;if(c&&c.startsWith("pill")){td=el("td");td.append(el("span",c,v))}else if(c==="ip"){td=el("td","ip");td.append(ipTag(v,cc));td.onclick=()=>openIp(v)}else{td=el("td",c||"",v)}tr.append(td)});tb.append(tr)});
 t.replaceChildren(thead,tb)}

/* ---------- Boucle d'actualisation ---------- */
let last=null,timer=null,paused=false;
function setStatus(cls,text){const s=$("#status");s.className="status"+(cls?" "+cls:"");$("#live").textContent=text}
async function refresh(){
 try{const r=await fetch("/api/stats",{cache:"no-store"});if(r.status===503){setStatus("paused","Import des logs en cours…");return}if(!r.ok)throw new Error(r.status);const d=await r.json();
  const prev=last;last=d;
  updateKpis(d.totals);drawChart(d.per_hour);updateDonut(d.totals.reussies,d.totals.tentatives);
  RANKS.forEach(([k,,,ip])=>updateRank(k,d[k]||[],ip));
  updateCountries(d.top_countries||[]);updateMap(d.ips||[]);renderIps();renderBans();updateHeat(d.heatmap||[]);updateBehaviours(d.top_tags||[]);updateFeatures(d.features||{},d.sensors||[]);if(curIp&&prev)loadIp();
  Object.keys(FEEDS).forEach(k=>{tabCount[k].textContent=d[k].length});
  renderFeed(!!prev);
  if(!paused)setStatus("","En direct · "+new Date().toLocaleTimeString("fr-FR"));
 }catch(e){setStatus("err","Impossible de lire les données")}}
function setPaused(p){paused=p;clearInterval(timer);$("#pause").replaceChildren(icon(p?"play":"pause"),p?"Reprendre":"Pause");
 if(p)setStatus("paused","En pause");else{refresh();timer=setInterval(refresh,REFRESH_MS)}}
$("#pause").onclick=()=>setPaused(!paused);
document.addEventListener("visibilitychange",()=>{if(!document.hidden&&!paused)refresh()});
setPaused(false);
