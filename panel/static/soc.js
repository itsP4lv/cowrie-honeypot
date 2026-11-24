"use strict";
/* Page SOC (/soc). Toutes les données viennent des attaquants : insertion avec textContent uniquement. */
const $=s=>document.querySelector(s);
const NS="http://www.w3.org/2000/svg";
const nf=new Intl.NumberFormat("fr-FR");
const nf1=new Intl.NumberFormat("fr-FR",{maximumFractionDigits:1});
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined&&text!==null)e.textContent=String(text);return e}
function svg(tag,attrs){const e=document.createElementNS(NS,tag);for(const k in attrs)e.setAttribute(k,attrs[k]);return e}
const CC_RE=/^[a-z]{2}$/;
const regionName=(()=>{try{const dn=new Intl.DisplayNames(["fr"],{type:"region"});return cc=>{try{return dn.of(cc.toUpperCase())}catch(e){return cc.toUpperCase()}}}catch(e){return cc=>cc.toUpperCase()}})();
function flag(cc){if(!cc||!CC_RE.test(cc))return el("span","flag none");const i=el("img","flag");i.src="/flags/"+cc+".svg";i.alt=cc.toUpperCase();i.title=regionName(cc);i.loading="lazy";return i}
const fmtTime=ts=>{const d=new Date(ts);return isNaN(d)?(ts||""):d.toLocaleString("fr-FR",{day:"2-digit",month:"2-digit",hour:"2-digit",minute:"2-digit"})};
const fmtDay=day=>{const d=new Date(day+"T00:00:00Z");return isNaN(d)?day:d.toLocaleDateString("fr-FR",{weekday:"short",day:"numeric",month:"short",timeZone:"UTC"})};
function dur(s){if(s==null)return"—";s=Math.max(0,Math.round(s));
 const j=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
 if(j)return j+" j"+(h?" "+h+" h":"");if(h)return h+" h"+(m?" "+m+" min":"");if(m)return m+" min"+(s%60&&m<10?" "+s%60+" s":"");return s%60+" s"}
const plural=(n,w,ws)=>nf.format(n)+" "+(n>1?(ws||w+"s"):w);

/* ---------- Thème (même réglage que le dashboard) ---------- */
const SUN='<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>';
const MOON='<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>';
function applyTheme(t){document.documentElement.dataset.theme=t;localStorage.setItem("theme",t);
 const s=svg("svg",{viewBox:"0 0 24 24",fill:"none",stroke:"currentColor","stroke-width":2,"stroke-linecap":"round","stroke-linejoin":"round"});s.innerHTML=t==="light"?MOON:SUN;$("#theme").replaceChildren(s)}
applyTheme(localStorage.getItem("theme")||(matchMedia("(prefers-color-scheme: light)").matches?"light":"dark"));
$("#theme").onclick=()=>{applyTheme(document.documentElement.dataset.theme==="light"?"dark":"light");if(last)drawDays(last.days)};

/* ---------- Rendu ---------- */
const LEVELS={"critique":["ko","Critique"],"élevé":["hi","Élevé"],"modéré":["warn","Modéré"],"faible":["ok","Faible"]};
const SEV={critique:"Critique",haute:"Haute",moyenne:"Moyenne",action:"Action"};
let last=null,sevFilter="";

function hero(d){
 const t=d.totals,r=d.rates,[cls,label]=LEVELS[d.threat.level]||LEVELS["modéré"];
 const lv=$("#level");lv.className="soc-level "+cls;lv.replaceChildren(el("small","","Niveau de menace"),el("b","",label),el("span","",d.threat.why));
 $("#hero").className="card soc-hero "+cls;
 $("#headline").textContent=`En ligne depuis ${dur(d.uptime)} : ${plural(t.connexions,"connexion")} de ${plural(t.ips,"IP unique","IP uniques")} venant de ${plural(t.pays,"pays","pays")}.`;
 $("#story").textContent=story(d).join(" ");
}

function story(d){
 const t=d.totals,r=d.rates,out=[];
 if(r.every_s)out.push(`Soit une connexion toutes les ${dur(r.every_s)} en moyenne (≈ ${nf1.format(r.per_hour)} par heure, ${nf.format(Math.round(r.per_day))} par jour).`);
 const fl=d.milestones.find(m=>m.label==="Première tentative de login");
 if(fl)out.push(`Le premier essai de mot de passe est arrivé ${dur(fl.after)} après la première connexion.`);
 if(t.tentatives)out.push(`${plural(t.tentatives,"tentative")} de login, dont ${plural(t.reussies,"réussie")} (${nf1.format(r.login_success)} %) par ${plural(t.ips_reussies,"IP")}.`);
 if(t.commandes||t.fichiers)out.push(`Une fois « dedans », ils ont tapé ${plural(t.commandes,"commande")} et déposé ${plural(t.fichiers,"fichier")}${t.fichiers_uniques?` (${nf.format(t.fichiers_uniques)} différents)`:""}.`);
 if(d.busiest_day)out.push(`Jour le plus chargé : ${fmtDay(d.busiest_day.day)} (${plural(d.busiest_day.connexions,"connexion")}).`);
 if(t.revenues)out.push(`${plural(t.revenues,"IP est revenue","IP sont revenues")} sur plusieurs jours.`);
 if(t.bannies)out.push(`${plural(t.bannies,"IP bannie","IP bannies")}, dont ${nf.format(t.bannies_auto)} automatiquement.`);
 return out}

function kpis(d){
 const t=d.totals,r=d.rates,l=d.last24h;
 const K=[["Connexions",t.connexions,`≈ ${nf1.format(r.per_hour)} / heure`,"--acc"],
  ["IP uniques",t.ips,`+${nf.format(l.nouvelles_ips)} nouvelles en 24 h`,"--info"],
  ["Pays",t.pays,`${nf.format(d.continents.length)} continents`,"--vio"],
  ["Tentatives de login",t.tentatives,`${nf1.format(r.login_success)} % réussies`,"--acc2"],
  ["Bots connectés",t.ips_reussies,`${plural(t.reussies,"login réussi","logins réussis")}`,"--ko"],
  ["Commandes",t.commandes,`${nf.format(d.last24h.commandes)} en 24 h`,"--ok"],
  ["Fichiers déposés",t.fichiers,`${nf.format(t.fichiers_uniques)} différents`,"--ko"],
  ["IP bannies",t.bannies,`${nf.format(t.bannies_auto)} automatiquement`,"--mut"]];
 $("#kpis").replaceChildren(...K.map(([lbl,v,sub,c])=>{const k=el("div","card kpi");k.style.setProperty("--c",`var(${c})`);
  k.append(el("div","val",nf.format(v)),el("div","lbl",lbl),el("div","soc-sub",sub));return k}))}

function drawDays(days){
 const box=$("#days");box.replaceChildren();if(!days.length)return;
 const W=Math.max(320,box.clientWidth||700),H=240,P={l:44,r:44,t:12,b:28},iw=W-P.l-P.r,ih=H-P.t-P.b;
 const s=svg("svg",{viewBox:`0 0 ${W} ${H}`,width:"100%",height:H});
 const max=Math.max(1,...days.map(x=>x.connexions));let cum=0;const cums=days.map(x=>cum+=x.nouvelles_ips),cmax=Math.max(1,cum);
 const bw=iw/days.length,y=v=>P.t+ih-ih*v/max,yc=v=>P.t+ih-ih*v/cmax;
 for(let i=0;i<=4;i++){const v=max*i/4,yy=y(v);s.append(svg("line",{class:"gl",x1:P.l,x2:W-P.r,y1:yy,y2:yy}));
  const a=svg("text",{class:"ax",x:P.l-6,y:yy+3,"text-anchor":"end"});a.textContent=nf.format(Math.round(v));s.append(a);
  const b=svg("text",{class:"ax",x:W-P.r+6,y:yc(cmax*i/4)+3});b.textContent=nf.format(Math.round(cmax*i/4));s.append(b)}
 const step=Math.ceil(days.length/10);let line="";
 days.forEach((x,i)=>{const x0=P.l+i*bw,h=ih*x.connexions/max;
  const bwid=Math.min(bw*.7,56),rect=svg("rect",{x:x0+(bw-bwid)/2,y:P.t+ih-h,width:Math.max(1,bwid),height:h,rx:3,fill:"var(--acc)","fill-opacity":.75});
  const tt=svg("title",{});tt.textContent=`${fmtDay(x.day)} : ${plural(x.connexions,"connexion")}, ${plural(x.ips,"IP")} (${nf.format(x.nouvelles_ips)} nouvelles), ${plural(x.reussies,"login réussi","logins réussis")}, ${plural(x.commandes,"commande")}`;rect.append(tt);s.append(rect);
  line+=(i?"L":"M")+(x0+bw/2).toFixed(1)+","+yc(cums[i]).toFixed(1);
  if(i%step===0){const a=svg("text",{class:"ax",x:x0+bw/2,y:H-8,"text-anchor":"middle"});a.textContent=fmtDay(x.day);s.append(a)}});
 s.append(svg("path",{d:line,fill:"none",stroke:"var(--info)","stroke-width":2.2,"stroke-linejoin":"round"}));
 days.forEach((x,i)=>s.append(svg("circle",{cx:P.l+i*bw+bw/2,cy:yc(cums[i]),r:3,fill:"var(--info)"})));
 const lg=el("div","soc-legend");const a=el("span","","Connexions / jour");a.style.setProperty("--c","var(--acc)");const b=el("span","","IP uniques cumulées");b.style.setProperty("--c","var(--info)");lg.append(a,b);
 box.append(s,lg)}

function trend(d){
 const rows=[["Connexions","connexions"],["IP uniques","ips"],["Logins réussis","reussies"],["Commandes","commandes"]];
 const box=$("#trend");box.replaceChildren(...rows.map(([lbl,k])=>{const a=d.last24h[k]||0,b=d.prev24h[k]||0;
  const r=el("div","soc-trow"),v=el("b","",nf.format(a));let delta;
  if(!b)delta=el("span","soc-delta",a?"nouveau":"—");
  else{const p=Math.round(100*(a-b)/b);delta=el("span","soc-delta "+(p>10?"up":p<-10?"down":""),(p>0?"▲ +":p<0?"▼ ":"= ")+p+" %")}
  const l=el("div");l.append(el("span","",lbl),el("small","muted","avant : "+nf.format(b)));r.append(l,v,delta);return r}));
 const h=el("div","soc-trow");const l=el("div");l.append(el("span","","Dernière heure"),el("small","muted",`moyenne : ${nf1.format(d.rates.per_hour)} / h`));
 h.append(l,el("b","",nf.format(d.last1h.connexions)),el("span","soc-delta "+(d.threat.ratio>=2?"up":d.threat.ratio<.5?"down":""),"× "+nf1.format(d.threat.ratio)));box.append(h);
 if(d.peak_hour){const p=el("p","muted soc-note");p.textContent=`Heure la plus chargée : ${fmtTime(d.peak_hour.hour)} (${plural(d.peak_hour.connexions,"connexion")}).`;box.append(p)}}

function ipCell(ip,cc){const td=el("td","ip");if(!ip){td.textContent="—";return td}
 const a=el("a","");a.href="/honeypot#ip="+encodeURIComponent(ip);a.append(flag(cc)," ",ip);td.append(a);return td}

function incidents(d){
 const counts={};d.incidents.forEach(i=>counts[i.sev]=(counts[i.sev]||0)+1);
 $("#filters").replaceChildren(...[["","Tout",d.incidents.length],...Object.keys(SEV).map(k=>[k,SEV[k],counts[k]||0])].map(([k,l,n])=>{
  const b=el("button","btn sm"+(sevFilter===k?" on":""),`${l} · ${nf.format(n)}`);b.type="button";b.onclick=()=>{sevFilter=k;incidents(last)};return b}));
 const list=d.incidents.filter(i=>!sevFilter||i.sev===sevFilter);
 const body=$("#incidents");
 if(!list.length){const r=el("tr"),c=el("td","muted","Aucun incident");c.colSpan=5;r.append(c);body.replaceChildren(r);return}
 body.replaceChildren(...list.map(i=>{const r=el("tr");const s=el("td");s.append(el("span","pill sev-"+i.sev,SEV[i.sev]||i.sev));
  r.append(el("td","t",fmtTime(i.ts)),s,el("td","",i.type),ipCell(i.ip,i.cc),el("td","code",i.detail||""));return r}))}

function timeline(d){
 $("#timeline").replaceChildren(...d.milestones.map(m=>{const li=el("li");
  const h=el("div","soc-tl-h");h.append(el("b","",m.label),el("span","muted",m.after?"+ "+dur(m.after):"T0"));
  li.append(h,el("div","muted",fmtTime(m.ts)));
  if(m.ip||m.detail){const x=el("div","soc-tl-d");if(m.ip){const a=el("a","");a.href="/honeypot#ip="+encodeURIComponent(m.ip);a.append(flag(m.cc)," ",m.ip);x.append(a)}
   if(m.detail)x.append(el("code","",m.detail));li.append(x)}
  return li}))}

function bars(sel,rows,label,value,extra){
 const max=Math.max(1,...rows.map(value));
 $(sel).replaceChildren(...(rows.length?rows:[null]).map(r=>{if(!r)return el("p","muted","Pas encore de données");
  const w=el("div","soc-bar"),t=el("div","soc-bar-t");const l=el("span","");label(r,l);t.append(l,el("b","",nf.format(value(r))));
  const tr=el("div","soc-bar-tr"),f=el("i");f.style.width=(100*value(r)/max).toFixed(1)+"%";tr.append(f);w.append(t,tr);
  if(extra)w.append(el("small","muted",extra(r)));return w}))}

function render(d){
 last=d;
 if(d.empty){$("#headline").textContent="Aucun événement pour l'instant : le honeypot attend ses premiers visiteurs.";return}
 hero(d);kpis(d);drawDays(d.days);trend(d);incidents(d);timeline(d);
 bars("#services",d.services,(r,l)=>l.append(r.name+(r.port?" · port "+r.port:"")),r=>r.connexions,r=>plural(r.ips,"IP"));
 bars("#asn",d.top_asn,(r,l)=>l.append(flag(r.cc)," ",(r.org||"?")+" · AS"+r.asn),r=>r.ips);
 bars("#continents",d.continents,(r,l)=>l.append(r.name),r=>r.ips)}

/* ---------- Rapport texte (pour un message, un compte rendu…) ---------- */
function report(d){
 const t=d.totals,L=[];
 L.push(`RAPPORT SOC – honeypot – ${new Date(d.now).toLocaleString("fr-FR")}`,"");
 L.push(`En ligne depuis ${dur(d.uptime)} (depuis le ${new Date(d.online_since).toLocaleString("fr-FR")}).`);
 L.push(`${plural(t.connexions,"connexion")} de ${plural(t.ips,"IP unique","IP uniques")} venant de ${plural(t.pays,"pays","pays")}.`);
 L.push(...story(d),"");
 L.push(`Niveau de menace : ${(LEVELS[d.threat.level]||[,""])[1]} (${d.threat.why}).`);
 L.push(`Dernières 24 h : ${plural(d.last24h.connexions,"connexion")}, ${plural(d.last24h.ips,"IP")} (${nf.format(d.last24h.nouvelles_ips)} nouvelles), ${plural(d.last24h.reussies,"login réussi","logins réussis")}.`,"");
 if(d.services.length)L.push("Services visés : "+d.services.map(s=>`${s.name} ${nf.format(s.connexions)}`).join(", ")+".");
 if(d.top_asn.length)L.push("Opérateurs les plus actifs : "+d.top_asn.slice(0,5).map(a=>`${a.org||"AS"+a.asn} (${a.ips} IP)`).join(", ")+".");
 L.push("","Chronologie :",...d.milestones.map(m=>`- ${fmtTime(m.ts)} (+${dur(m.after)}) : ${m.label}`));
 return L.join("\n")}
$("#copy").onclick=async()=>{if(!last||last.empty)return;const b=$("#copy");
 try{await navigator.clipboard.writeText(report(last));b.textContent="Copié ✓"}catch(e){b.textContent="Copie impossible"}
 setTimeout(()=>b.textContent="Copier le rapport",2000)};

/* ---------- Actualisation ---------- */
async function refresh(){
 try{const r=await fetch("/api/soc",{cache:"no-store"});if(r.status===503){$("#live").textContent="import des logs…";return}
  if(!r.ok)throw new Error(r.status);render(await r.json());
  $("#status").className="status";$("#live").textContent="à jour · "+new Date().toLocaleTimeString("fr-FR")}
 catch(e){$("#status").className="status err";$("#live").textContent="hors connexion"}}
let rz;addEventListener("resize",()=>{clearTimeout(rz);rz=setTimeout(()=>last&&!last.empty&&drawDays(last.days),150)});
refresh();setInterval(()=>{if(!document.hidden)refresh()},30000);
