const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
// Sprache und Übersetzungen legt der Server fest (siehe locales/*.json) und fügt sie in die Seite ein
const LANG=(window.I18N&&window.I18N.lang)||'en',UI=(window.I18N&&window.I18N.ui)||{};
const t=(s,...a)=>{const r=UI[s]!==undefined?UI[s]:s;return a.length?r.replace(/\{(\d+)\}/g,(m,i)=>a[i]):r};
function applyI18n(){
  document.documentElement.lang=LANG;
  document.querySelectorAll('[data-i18n]').forEach(el=>{for(const n of el.childNodes)if(n.nodeType===3&&n.data.trim()){n.data=n.data.replace(n.data.trim(),t(n.data.trim()));break}});
  document.querySelectorAll('[data-i18n-attr]').forEach(el=>el.dataset.i18nAttr.split(',').forEach(a=>el.setAttribute(a,t(el.getAttribute(a)))));
}
applyI18n();

let BASEDN='',ME='',cur=null,kids={},open=new Set(),sel='';
async function api(p,m='GET',b){
  const r=await fetch('/api/'+p,{method:m,headers:{'Content-Type':'application/json','Accept-Language':LANG},body:b?JSON.stringify(b):undefined});
  const d=await r.json().catch(()=>({}));
  if(r.status===401&&p!=='login'){show(false);throw new Error(d.error)}
  if(!r.ok)throw new Error(d.error||t('Request failed'));
  return d;
}
function toast(t){const e=$('#toast');e.textContent=t;e.classList.add('on');setTimeout(()=>e.classList.remove('on'),2200)}
function show(on){$('#login').classList.toggle('hidden',on);$('#app').classList.toggle('hidden',!on)}

$('#lf').onsubmit=async e=>{e.preventDefault();$('#le').textContent='';
  try{await api('login','POST',{user:$('#lu').value,password:$('#lp').value});$('#lp').value='';await start()}
  catch(x){$('#le').textContent=x.message}};
$('#out').onclick=async()=>{await api('logout','POST');show(false)};
$('#imp').onclick=()=>importForm();
$('#acl').onclick=()=>aclForm();
$('#sq').oninput=()=>{clearTimeout(sTimer);sTimer=setTimeout(runSearch,250)};
$('#sq').onkeydown=e=>{
  if(e.key==='Escape'){e.target.value='';runSearch()}
  if(e.key==='Enter'){const f=$('#sr .res');if(f)f.click()}
};
$('#sf').querySelectorAll('button').forEach(b=>b.onclick=()=>{sType=b.dataset.t;$('#sf').querySelectorAll('button').forEach(x=>x.setAttribute('aria-pressed',x===b));runSearch()});

async function start(){
  const m=await api('me');BASEDN=m.base;ME=m.dn;TPL.group.x='uniqueMember: '+ME;$('#base').textContent=m.base;show(true);await load();
}
async function load(){kids={};if(!sel)sel=BASEDN;renderTree();showEntry(sel);if(searchActive())runSearch()}
const TW_MIN=200,TW_MAX=600;
function treeManual(){try{return !!localStorage.getItem('tw2')}catch(e){return false}}
function autoWidth(){ // Spalte an den längsten sichtbaren Eintrag anpassen, solange nicht von Hand verstellt
  if(treeManual()||$('#tt').classList.contains('hidden'))return;
  const T=$('#tt'),L=T.getBoundingClientRect().left;
  let need=0;
  T.querySelectorAll('.tb span').forEach(x=>{need=Math.max(need,x.getBoundingClientRect().right-L)});
  $('#tree').style.setProperty('--tw',Math.round(Math.min(Math.max(need+32,TW_MIN),TW_MAX))+'px');
}
async function fetchKids(dn){kids[dn]=await api('tree?dn='+encodeURIComponent(dn))}
function nodeHtml(n){
  const o=open.has(n.dn),ch=kids[n.dn]||[];
  return `<li><div class="tn${sel===n.dn?' sel':''}" data-dn="${esc(n.dn)}" data-kind="${n.kind}" ${n.dn===BASEDN?'':'draggable="true"'}><button class="tg" data-t="${esc(n.dn)}" ${n.kids?'':'disabled'} aria-label="${o?'Zuklappen':'Aufklappen'}" aria-expanded="${o}">${n.kids?(o?'▾':'▸'):''}</button><button class="tb k-${n.kind}" data-s="${esc(n.dn)}" title="${esc(n.dn)}"><span>${esc(n.rdn)}</span></button></div>${o&&ch.length?`<ul>${ch.map(nodeHtml).join('')}</ul>`:''}</li>`;
}
async function renderTree(){
  open.add(BASEDN);
  await Promise.all([...open].filter(d=>!kids[d]).map(d=>fetchKids(d).catch(e=>{open.delete(d);toast(e.message)})));
  const T=$('#tt');
  T.innerHTML='<ul>'+nodeHtml({dn:BASEDN,rdn:BASEDN,kind:'ou',kids:true})+'</ul>';
  T.querySelectorAll('.tg:not([disabled])').forEach(b=>b.onclick=()=>{const d=b.dataset.t;open.has(d)?open.delete(d):open.add(d);renderTree()});
  T.querySelectorAll('.tb').forEach(b=>b.onclick=()=>{sel=b.dataset.s;renderTree();showEntry(sel)});
  T.querySelectorAll('.tn').forEach(r=>{
    r.ondragstart=e=>{e.dataTransfer.setData('text/plain',r.dataset.dn);e.dataTransfer.effectAllowed='move'};
    if(r.dataset.kind!=='ou')return;
    r.ondragover=e=>{e.preventDefault();r.classList.add('drop')};
    r.ondragleave=()=>r.classList.remove('drop');
    r.ondrop=e=>{e.preventDefault();r.classList.remove('drop');const dn=e.dataTransfer.getData('text/plain');if(dn&&dn!==r.dataset.dn)moveEntry(dn,r.dataset.dn,true)};
  });
  autoWidth();
}
async function showEntry(dn){
  const D=$('#td');
  try{
    const e=cur=await api('entry?dn='+encodeURIComponent(dn)),base=dn.toLowerCase()===BASEDN.toLowerCase();
    D.innerHTML=`<h2>${esc(dn.split(',')[0])}</h2><span class="dn">${esc(dn)}</span>
    <div class="acts"><button class="btn" id="b-new">${t('Create below')}</button><button class="btn ghost" id="b-ed">${t('Edit')}</button><button class="btn ghost" id="b-ex">${t('Export')}</button>${base?'':'<button class="btn ghost" id="b-mv">'+t('Move')+'</button><button class="btn bad" id="b-del">'+t('Delete')+'</button>'}</div>
    <dl>${Object.entries(e.attrs).map(([k,v])=>`<dt>${esc(k)}</dt><dd>${valHtml(k,v)}</dd>`).join('')}</dl>`;
    $('#b-new').onclick=()=>createForm(e.dn);
    $('#b-ed').onclick=()=>editForm(e);
    $('#b-ex').onclick=()=>exportForm(e);
    if(!base){$('#b-mv').onclick=()=>moveForm(e);$('#b-del').onclick=()=>deleteEntry(e)}
  }catch(x){D.innerHTML=`<p class="err">${esc(x.message)}</p>`}
}
const collator=new Intl.Collator(LANG,{sensitivity:'base',numeric:true});
function valHtml(k,v){ // mehrwertige Attribute alphabetisch anzeigen, lange Listen scrollbar
  const vals=v.length>1&&k.toLowerCase()!=='objectclass'?[...v].sort(collator.compare):v;
  const h=vals.map(esc).join('<br>');
  return v.length>8?`<div class="many">${h}</div><span class="hint">${t('{0} values, sorted alphabetically',v.length)}</span>`:h;
}
function parseAttrs(t){const o={};t.split('\n').forEach(l=>{const i=l.indexOf(':');if(i<1)return;const k=l.slice(0,i).trim(),v=l.slice(i+1).trim();if(v)(o[k]=o[k]||[]).push(v)});return o}

const TPL={
  ou:{t:t('Organizational unit'),oc:'organizationalUnit',rdn:'ou',x:''},
  user:{t:t('User'),oc:'inetOrgPerson',rdn:'uid',x:'cn: \nsn: \ngivenName: \nmail: '},
  group:{t:t('Group'),oc:'groupOfUniqueNames',rdn:'cn',x:'uniqueMember: '+ME},
  own:{t:t('Custom entry'),oc:'',rdn:'cn',x:''}};
function ocOf(t){return Object.entries(parseAttrs(t)).filter(([k])=>k.toLowerCase()==='objectclass').flatMap(([,v])=>v)}
function attrHelper(box,ta,ocs,extra){
  let key='',data=[],tm;
  const draw=()=>{
    if(!data.length){box.innerHTML='';return}
    const have=new Set(Object.keys(parseAttrs(ta.value)).map(k=>k.toLowerCase()));
    box.innerHTML=`<span class="hint">${t('Available attributes – click to insert a line (* = required, dimmed = already present)')}</span><div class="chips">${data.map(a=>`<button type="button" class="chip${a.must?' must':''}${have.has(a.name.toLowerCase())?' have':''}" data-n="${esc(a.name)}" title="${esc((a.desc||'')+(a.single?t(' (single value only)'):''))}">${esc(a.name)}${a.must?' *':''}</button>`).join('')}</div>`;
    box.querySelectorAll('.chip').forEach(b=>b.onclick=()=>{const v=ta.value.replace(/\s+$/,'');ta.value=(v?v+'\n':'')+b.dataset.n+': ';ta.focus();ta.selectionStart=ta.selectionEnd=ta.value.length;draw()});
  };
  const run=async()=>{
    const l=ocs(),k=l.join(',').toLowerCase();
    if(k!==key){key=k;data=[];if(l.length){try{data=await api('schema?oc='+encodeURIComponent(l.join(',')))}catch(x){box.textContent=x.message;return}}}
    draw();
  };
  const later=()=>{clearTimeout(tm);tm=setTimeout(run,250)};
  ta.addEventListener('input',later);(extra||[]).forEach(e=>e.addEventListener('input',later));
  run();
}
function createForm(parent){
  dialog(`<h2>${t('Create entry')}</h2><span class="dn">${t('below {0}',esc(parent))}</span>
  <label>${t('Type')}<select name="tpl">${Object.entries(TPL).map(([k,v])=>`<option value="${k}">${v.t}</option>`).join('')}</select></label>
  <div class="two"><label>${t('RDN attribute')}<input name="ra" required></label><label>${t('RDN value')}<input name="rv" required></label></div>
  <label>${t('Object classes (comma-separated)')}<input name="oc" required></label>
  <label>${t('More attributes (one line per value: name: value)')}<textarea name="x" rows="5" spellcheck="false"></textarea></label>
  <div class="attrs"></div>
  <label>${t('Password (optional)')}<input name="pw" type="password" autocomplete="new-password"></label>`,
  async d=>{const r=await api('entry','POST',{parent,ra:d.ra,rv:d.rv,oc:d.oc.split(',').map(x=>x.trim()).filter(Boolean),attrs:parseAttrs(d.x),password:d.pw});open.add(parent);sel=r.dn});
  const f=$('#df'),fill=()=>{const t=TPL[f.elements.tpl.value];f.elements.ra.value=t.rdn;f.elements.oc.value=t.oc;f.elements.x.value=t.x};
  fill();
  attrHelper(f.querySelector('.attrs'),f.elements.x,()=>f.elements.oc.value.split(',').map(x=>x.trim()).filter(Boolean),[f.elements.oc]);
  f.elements.tpl.onchange=()=>{fill();f.elements.oc.dispatchEvent(new Event('input'))};
}
function editForm(e){
  const ed=Object.entries(e.attrs).filter(([k,v])=>!/^userpassword$/i.test(k)&&!v.some(x=>/^‹(binary|binär)/.test(x)));
  const lines=ed.flatMap(([k,v])=>v.map(x=>k+': '+x)).join('\n');
  dialog(`<h2>${t('Edit entry')}</h2><span class="dn">${esc(e.dn)}</span>
  <label>${t('Attributes (one line per value; missing lines are removed)')}<textarea name="x" rows="12" spellcheck="false">${esc(lines)}</textarea></label>
  <div><button type="button" class="btn ghost" id="sortv" title="${t('Sorts the values within each attribute alphabetically')}">${t('Sort values')}</button></div>
  <div class="attrs"></div>
  <label>${t('New password')}<input name="pw" type="password" autocomplete="new-password" placeholder="${t('Leave empty to keep it')}"></label>`,
  async d=>{
    const o={},n={},ch={};
    ed.forEach(([k,v])=>o[k.toLowerCase()]={k,v});
    Object.entries(parseAttrs(d.x)).forEach(([k,v])=>n[k.toLowerCase()]={k,v});
    new Set([...Object.keys(o),...Object.keys(n)]).forEach(l=>{const a=(o[l]||{v:[]}).v,b=(n[l]||{v:[]}).v;if(a.join('\n')!==b.join('\n'))ch[(o[l]||n[l]).k]=b});
    await api('entry','PUT',{dn:e.dn,attrs:ch,password:d.pw});sel=e.dn;
  });
  const f=$('#df');
  attrHelper(f.querySelector('.attrs'),f.elements.x,()=>ocOf(f.elements.x.value));
  $('#sortv').onclick=()=>{
    const ta=f.elements.x,g=new Map();
    ta.value.split('\n').forEach(l=>{const i=l.indexOf(':');if(i<1)return;const k=l.slice(0,i).trim(),v=l.slice(i+1).trim();if(!v)return;const key=k.toLowerCase();if(!g.has(key))g.set(key,{k,v:[]});g.get(key).v.push(v)});
    ta.value=[...g.values()].flatMap(({k,v})=>(k.toLowerCase()==='objectclass'?v:[...v].sort(collator.compare)).map(x=>k+': '+x)).join('\n');
    ta.dispatchEvent(new Event('input'));
  };
}
async function moveForm(e){
  const dn=e.dn.toLowerCase();
  const cs=(await api('containers')).filter(d=>d.toLowerCase()!==dn&&!d.toLowerCase().endsWith(','+dn));
  dialog(`<h2>${t('Move entry')}</h2><span class="dn">${esc(e.dn)}</span>
  <label>${t('New parent entry')}<select name="t">${cs.map(d=>`<option ${d===e.parent?'selected':''}>${esc(d)}</option>`).join('')}</select></label>`,
  async d=>{const r=await api('move','POST',{dn:e.dn,target:d.t});open.add(d.t);sel=r.dn});
}
async function moveEntry(dn,target,ask){
  if(ask&&!confirm(t('Move entry?')+'\n\n'+dn+'\n→ '+target))return;
  try{const r=await api('move','POST',{dn,target});open.add(target);sel=r.dn;toast(t('Moved'));await load()}catch(x){toast(x.message)}
}
async function deleteEntry(e){
  if(!confirm(t('Really delete this entry?')+'\n\n'+e.dn))return;
  const u='entry?dn='+encodeURIComponent(e.dn);
  try{
    try{await api(u,'DELETE')}
    catch(x){if(!/NonLeaf/i.test(x.message))throw x;
      if(!confirm(t('The entry has child entries. Delete everything below it as well?')))return;
      await api(u+'&recursive=1','DELETE')}
    sel=e.parent;toast(t('Deleted'));await load();
  }catch(x){toast(x.message)}
}

async function download(path){
  const r=await fetch('/api/'+path,{headers:{'Accept-Language':LANG}});
  if(r.status===401){show(false);throw new Error(t('Session expired'))}
  if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.error||t('Export failed'))}
  const m=/filename="([^"]+)"/.exec(r.headers.get('Content-Disposition')||'');
  const a=document.createElement('a');a.href=URL.createObjectURL(await r.blob());a.download=m?m[1]:'export.ldif';
  document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),4000);
}
function exportForm(e){
  dialog(`<h2>${t('Export as LDIF')}</h2><span class="dn">${esc(e.dn)}</span>
  <label class="chk"><input type="radio" name="scope" value="base"> ${t('This entry only')}</label>
  <label class="chk"><input type="radio" name="scope" value="subtree" checked> ${t('Entry with all child entries')}</label>
  <label class="chk"><input type="checkbox" name="pw"> ${t('Include password hashes (userPassword)')}</label>`,
  async d=>{await download('export?dn='+encodeURIComponent(e.dn)+'&scope='+d.scope+'&pw='+(d.pw?1:0));return t('Export downloaded')},null,t('Export'));
}
function importForm(){
  dialog(`<h2>${t('Import LDIF')}</h2>
  <label>${t('Choose file')}<input type="file" id="imf" accept=".ldif,.txt,text/plain"></label>
  <label>${t('or paste LDIF')}<textarea name="ldif" rows="10" spellcheck="false"></textarea></label>
  <label class="chk"><input type="checkbox" name="skip" checked> ${t('Skip existing entries')}</label>
  <label class="chk"><input type="checkbox" name="cont"> ${t('Continue with the next entry on errors')}</label>
  <div><button type="button" class="btn ghost" id="imchk">${t('Check')}</button> <span class="hint" id="imsg"></span></div>`,
  async d=>{
    const r=await api('import','POST',{ldif:d.ldif,apply:true,skip:!!d.skip,cont:!!d.cont});
    if(r.errors.length){await load();throw new Error(t('{0} of {1} imported, {2} skipped, {3} errors:',r.ok,r.total,r.skipped,r.errors.length)+'\n'+r.errors.slice(0,5).join('\n')+(r.errors.length>5?'\n…':''))}
    return t('{0} imported',r.ok)+(r.skipped?t(', {0} skipped',r.skipped):'');
  },null,t('Import'));
  const f=$('#df'),names={add:t('to create'),modify:t('to change'),delete:t('to delete')};
  $('#imf').onchange=async e=>{const t=e.target.files[0];if(t)f.elements.ldif.value=await t.text()};
  $('#imchk').onclick=async()=>{
    try{const r=await api('import','POST',{ldif:f.elements.ldif.value});$('#imsg').textContent=t('{0} entries recognized: ',r.count)+Object.entries(r.ops).map(([k,v])=>v+' '+names[k]).join(', ')}
    catch(x){$('#imsg').textContent=x.message}
  };
}
let sTimer=0,sSeq=0,sType='all';
const searchActive=()=>$('#sq').value.trim().length>=2;
function reveal(dn){ // alle übergeordneten Einträge im Baum aufklappen
  const p=dn.split(/(?<!\\),/);
  for(let i=1;i<p.length;i++){const a=p.slice(i).join(',');if(a.toLowerCase().endsWith(BASEDN.toLowerCase()))open.add(a)}
}
async function runSearch(){
  const q=$('#sq').value.trim(),R=$('#sr');
  $('#tt').classList.toggle('hidden',q.length>=2);R.classList.toggle('hidden',q.length<2);
  if(q.length<2){renderTree();return}
  if(!treeManual())$('#tree').style.setProperty('--tw','340px'); // Platz für die Trefferliste
  const my=++sSeq;
  try{
    const r=await api('search?q='+encodeURIComponent(q)+'&type='+sType);
    if(my!==sSeq)return;
    R.innerHTML=r.items.length?r.items.map(i=>`<button class="res k-${i.kind}${i.dn===sel?' sel':''}" data-dn="${esc(i.dn)}"><span class="rw"><strong>${esc(i.cn)}</strong>${i.mail?`<span class="rm">${esc(i.mail)}</span>`:''}<span class="dn">${esc(i.dn)}</span></span></button>`).join('')+(r.more?'<div class="empty">'+t('Only the first 100 results. Please refine your search.')+'</div>':''):'<div class="empty">'+t('No results.')+'</div>';
    R.querySelectorAll('.res').forEach(b=>b.onclick=()=>{sel=b.dataset.dn;reveal(sel);R.querySelectorAll('.res').forEach(x=>x.classList.toggle('sel',x===b));showEntry(sel)});
  }catch(x){if(my===sSeq)R.innerHTML=`<p class="err">${esc(x.message)}</p>`}
}
function aclForm(){
  dialog('<h2>'+t('Permissions')+'</h2><div id="aclbox"><span class="hint">'+t('Loading …')+'</span></div>',async()=>false,null,t('Close'));
  $('#df').addEventListener('keydown',e=>{if(e.key==='Enter'&&e.target.tagName==='INPUT')e.preventDefault()});
  aclRender();
}
async function aclRender(){
  const B=$('#aclbox');
  let r;
  try{r=await api('acl')}catch(x){B.innerHTML=`<p class="err">${esc(x.message)}</p>`;return}
  if(r.needLogin){
    B.innerHTML=`<span class="hint">${t('Permissions are stored in the server configuration (cn=config). You need an account with write access to it, e.g. cn=admin,cn=config. The credentials are kept only in this session’s memory.')}</span>
    <label>${t('Configuration DN')}<input id="cd" value="${esc(r.dn)}"></label>
    <label>${t('Password')}<input id="cp" type="password" autocomplete="off"></label>
    <p class="err" id="ce"></p><div><button type="button" class="btn" id="cl">${t('Log in')}</button></div>`;
    const go=async()=>{try{await api('acl/login','POST',{dn:$('#cd').value,password:$('#cp').value});aclRender()}catch(x){$('#ce').textContent=x.message}};
    $('#cl').onclick=go;$('#cp').onkeydown=e=>{if(e.key==='Enter')go()};
    return;
  }
  const rows=r.grants.map(g=>`<div class="grant"><span class="tag">${g.kind==='group'?t('Group'):t('User')}</span><span class="dn">${esc(g.who)}${g.scope.toLowerCase()===BASEDN.toLowerCase()?'':'<br>'+t('Scope: {0}',esc(g.scope))}</span><span class="tag">${esc(g.level)}</span><button type="button" class="btn bad" data-r="${esc(g.rule)}">${t('Revoke')}</button></div>`).join('');
  B.innerHTML=`<span class="hint">${t('Database: {0}',esc(r.db))}<br>${t('Configuration account: {0}',esc(r.user))}${r.root?'<br>'+t('Root DN (always has full rights): {0}',esc(r.root)):''}</span>
  <h3>${t('Write permissions')}</h3>
  ${rows||'<span class="hint">'+t('No additional write permissions granted yet.')+'</span>'}
  <h3>${t('Grant new')}</h3>
  <label>${t('User or group')}<input id="aw" list="awl" placeholder="${t('Type a name or paste a DN')}" autocomplete="off"><datalist id="awl"></datalist></label>
  <div class="two"><label>${t('Scope')}<input id="as" value="${esc(BASEDN)}"></label>
  <label>${t('Level')}<select id="al"><option value="write">${t('write: read and write')}</option><option value="manage">${t('manage: full administration')}</option></select></label></div>
  <p class="err" id="ae"></p><div><button type="button" class="btn" id="ag">${t('Grant permission')}</button></div>
  <details><summary class="hint">${t('Other server rules (display only, not modified)')}</summary><pre>${esc(r.others.join('\n\n')||'–')}</pre></details>
  <span class="hint">${t('Permissions take effect immediately. The rules are placed at the very top and leave all other server rules unchanged. Anyone who receives write permissions logs in here with their own DN.')}</span>`;
  let tm;
  $('#aw').oninput=()=>{clearTimeout(tm);tm=setTimeout(async()=>{
    const q=$('#aw').value.trim();if(q.length<2||q.includes('='))return;
    try{const l=await api('lookup?q='+encodeURIComponent(q));$('#awl').innerHTML=l.map(x=>`<option value="${esc(x.dn)}">${esc(x.cn)} (${x.kind==='group'?t('Group'):t('User')})</option>`).join('')}catch(x){}
  },250)};
  $('#ag').onclick=async()=>{
    try{await api('acl/grant','POST',{who:$('#aw').value,scope:$('#as').value,level:$('#al').value});toast(t('Permission granted'));aclRender()}
    catch(x){$('#ae').textContent=x.message}
  };
  B.querySelectorAll('[data-r]').forEach(b=>b.onclick=async()=>{
    if(!confirm(t('Revoke this permission?')))return;
    try{await api('acl/revoke','POST',{rule:b.dataset.r});toast(t('Permission revoked'));aclRender()}catch(x){toast(x.message)}
  });
}
function dialog(html,onSave,onDelete,ok){
  const f=$('#df');
  f.innerHTML=html+`<p class="err" id="de"></p><div class="acts">${onDelete?'<button type="button" class="btn bad" id="dd">'+t('Delete')+'</button><span class="sp"></span>':''}<button type="button" class="btn ghost" id="dc">${t('Cancel')}</button><button class="btn">${ok||t('Save')}</button></div>`;
  $('#dc').onclick=()=>$('#dlg').close();
  if(onDelete)$('#dd').onclick=async()=>{if(!confirm(t('Really delete this entry?')))return;try{await onDelete();$('#dlg').close();toast(t('Deleted'));load()}catch(x){$('#de').textContent=x.message}};
  f.onsubmit=async e=>{e.preventDefault();try{const m=await onSave(Object.fromEntries(new FormData(f)));$('#dlg').close();if(m!==false)toast(typeof m==='string'?m:t('Saved'));load()}catch(x){$('#de').textContent=x.message}};
  $('#dlg').showModal();
}

(()=>{
  const S=$('#tree'),G=$('#gp');
  try{const w=parseInt(localStorage.getItem('tw2'));if(w>=160&&w<=600)S.style.setProperty('--tw',w+'px')}catch(e){}
  const set=x=>{const w=Math.max(160,Math.min(x,600,S.clientWidth-360))+'px';S.style.setProperty('--tw',w);try{localStorage.setItem('tw2',w)}catch(e){}};
  G.onpointerdown=e=>{G.setPointerCapture(e.pointerId);G.classList.add('on')};
  G.onpointermove=e=>{if(G.classList.contains('on'))set(e.clientX-S.getBoundingClientRect().left-8)};
  G.onpointerup=()=>G.classList.remove('on');
  G.ondblclick=()=>{try{localStorage.removeItem('tw2')}catch(e){};autoWidth()};
  G.onkeydown=e=>{const w=$('#tt').offsetWidth;if(e.key==='ArrowLeft')set(w-20);if(e.key==='ArrowRight')set(w+20)};
})();
api('me').then(start).catch(()=>show(false));
