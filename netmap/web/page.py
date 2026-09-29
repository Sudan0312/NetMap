"""The single-page dashboard served by `netmap serve`.

Plain HTML + vanilla JS, no build step and no CDN: the page only ever talks to
`/api/*` on its own origin using relative URLs, so it works from the preview
iframe, from `http://localhost:8080`, or from a jump host with port forwarding.
"""

from __future__ import annotations

import html

from .. import __version__


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)

_STYLE = """
:root{--bg:#0b1220;--panel:#111a2b;--panel2:#0e1626;--ink:#e6edf7;--muted:#93a4bd;
--line:#1e2b42;--critical:#ff5a52;--high:#ff9f43;--medium:#ffd166;--low:#5aa9ff;
--info:#9aa7bd;--ok:#2dd4a7;--accent:#7aa2ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 ui-sans-serif,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent)}
header{display:flex;gap:14px;align-items:center;justify-content:space-between;padding:12px 18px;
border-bottom:1px solid var(--line);background:linear-gradient(180deg,#0d1526,#0b1220);position:sticky;top:0;z-index:20}
header h1{font-size:15.5px;margin:0;letter-spacing:.3px;display:flex;gap:9px;align-items:center}
.pill{font-size:11px;padding:2px 9px;border-radius:999px;background:#16223a;border:1px solid var(--line);color:var(--muted)}
.scorebox{display:flex;align-items:center;gap:10px;font-weight:700}
.scorebox .n{font-size:22px}
main{display:grid;grid-template-columns:minmax(0,1fr) 380px;gap:14px;padding:14px 18px 40px;align-items:start}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.panel>h2{margin:0;padding:10px 13px;font-size:12.5px;text-transform:uppercase;letter-spacing:.08em;
color:var(--muted);border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:8px;align-items:center;flex-wrap:wrap}
.panel>.body{padding:12px 13px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(124px,1fr));gap:9px;margin-bottom:14px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:9px 11px}
.kpi .k{font-size:10.5px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}
.kpi .v{font-size:20px;font-weight:750;margin-top:2px}
.kpi .n{font-size:11px;color:var(--muted)}
button,select,input{font:inherit;color:var(--ink);background:#16223a;border:1px solid var(--line);border-radius:9px;padding:6px 10px}
button{cursor:pointer}
button:hover{border-color:var(--accent)}
button[aria-pressed=true]{background:var(--accent);color:#08101f;border-color:var(--accent);font-weight:650}
button.primary{background:var(--accent);color:#08101f;border-color:transparent;font-weight:700}
.tabs{display:flex;gap:6px;flex-wrap:wrap;padding:10px 13px 0}
.tabs button{border-bottom:none;border-radius:9px 9px 0 0;padding:6px 12px;background:#131e33}
.tabs button[aria-selected=true]{background:var(--panel);color:#fff;font-weight:700}
table{width:100%;border-collapse:collapse;font-size:12.6px}
th,td{padding:6px 8px;border-bottom:1px solid #18243a;text-align:left;vertical-align:top}
th{color:var(--muted);font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;background:#101a2c;position:sticky;top:0;cursor:pointer}
tbody tr:hover{background:#152036;cursor:pointer}
tr.crit td:first-child{box-shadow:inset 3px 0 0 var(--critical)}
tr.high td:first-child{box-shadow:inset 3px 0 0 var(--high)}
tr.medium td:first-child{box-shadow:inset 3px 0 0 var(--medium)}
tr.low td:first-child{box-shadow:inset 3px 0 0 var(--low)}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;font-size:10.5px;font-weight:700;color:#0b1220}
.chip.critical{background:var(--critical)}.chip.high{background:var(--high)}.chip.medium{background:var(--medium)}
.chip.low{background:var(--low)}.chip.info{background:var(--info)}.chip.ok{background:var(--ok)}
.chip.ghost{background:#22314d;color:var(--muted);font-weight:600}
.scroll{max-height:60vh;overflow:auto}
.svgwrap{background:#0a1120;overflow:auto;position:relative}
.svgwrap svg{display:block}
.node rect{cursor:pointer}
.dim{opacity:.18}
.muted-row{opacity:.35}
.drawer .fld{display:flex;justify-content:space-between;gap:10px;border-bottom:1px dashed #1c2941;padding:4px 0;font-size:12.5px}
.drawer .fld b{color:var(--muted);font-weight:600}
.finding{border:1px solid var(--line);border-left-width:4px;border-radius:9px;padding:8px 10px;margin:8px 0;background:var(--panel2)}
.finding.critical{border-left-color:var(--critical)}.finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--medium)}.finding.low{border-left-color:var(--low)}
.finding h4{margin:0 0 4px;font-size:13px}
.finding ul{margin:6px 0 0 16px;padding:0;font-size:12px;color:#c6d3e6}
.finding p{margin:5px 0 0;font-size:12px;color:#a9bbd3}
.note{font-size:11.5px;color:var(--muted)}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.grow{flex:1;min-width:140px}
progress{width:100%;height:8px}
code{background:#16223a;padding:1px 5px;border-radius:5px;font-size:11.5px}
footer{color:var(--muted);font-size:11.5px;text-align:center;padding:12px 0 34px}
@media (max-width:1180px){main{grid-template-columns:1fr}}
"""

_SCRIPT = r"""
var state = {snap:null, graph:null, findings:[], sel:null, sev:{}, q:''};

function api(path, opts){ return fetch(path, opts).then(function(r){ if(!r.ok) throw new Error(r.status+' '+path); return r.json(); }); }
function el(tag, cls, html){ var n=document.createElement(tag); if(cls) n.className=cls; if(html!==undefined) n.innerHTML=html; return n; }
function esc(s){ return String(s===null||s===undefined?'':s).replace(/[&<>"']/g, function(c){ return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]; }); }

function loadAll(){
  return Promise.all([api('/api/summary'), api('/api/graph'), api('/api/findings')]).then(function(res){
    state.snap=res[0]; state.graph=res[1]; state.findings=res[2];
    renderHeader(); renderKpis(); renderGraph(); renderFindings(); renderTables();
  }).catch(function(e){ document.getElementById('body').innerHTML='<div class="panel"><div class="body">No snapshot yet: '+esc(e.message)+'</div></div>'; });
}

function renderHeader(){
  var s=state.snap||{}, risk=s.risk||{};
  document.getElementById('score').innerHTML='<span class="n">'+(risk.score||0)+'</span><span class="pill">'+esc(risk.band||'unknown')+' risk</span>';
  document.getElementById('meta').textContent=(s.mode||'')+' · '+(s.devices||0)+' devices · '+(s.links||0)+' links · '+(s.finished||'');
}

function renderKpis(){
  var s=state.snap||{}, c=s.severity_counts||{}, t=s.topology||{}, d=s.devices_detail||{};
  var items=[
    ['Devices', s.devices||0, (d.undocumented||0)+' undocumented'],
    ['Critical', c.critical||0, (c.high||0)+' high'],
    ['Medium+', (c.medium||0)+(c.high||0)+(c.critical||0), (c.low||0)+' low'],
    ['Links', s.links||0, (t.bridges||0)+' SPOF'],
    ['Isolated', t.isolated_nodes||0, 'no adjacency found'],
    ['SNMP', (t.snmp_coverage_pct||0)+'%', 'devices readable'],
    ['Services', s.services||0, (s.ports||0)+' distinct'],
    ['Errors', s.scan_errors||0, 'scan stage']
  ];
  var wrap=document.getElementById('kpis'); wrap.innerHTML='';
  items.forEach(function(it){ var n=el('div','kpi'); n.innerHTML='<div class="k">'+esc(it[0])+'</div><div class="v">'+esc(it[1])+'</div><div class="n">'+esc(it[2])+'</div>'; wrap.appendChild(n); });
}

function renderGraph(){
  var g=state.graph||{nodes:[],links:[]}, W=g.width||1500, H=g.height||600;
  var NS='http://www.w3.org/2000/svg';
  var svg=document.createElementNS(NS,'svg');
  svg.setAttribute('viewBox','0 0 '+W+' '+H); svg.setAttribute('width','100%'); svg.setAttribute('height',H);
  (g.bands||[]).forEach(function(b){
    var r=document.createElementNS(NS,'rect');
    r.setAttribute('x',12); r.setAttribute('y',b.y0-14); r.setAttribute('width',W-24); r.setAttribute('height',b.height);
    r.setAttribute('rx',10); r.setAttribute('fill','#0d1728'); r.setAttribute('stroke','#1b2a44');
    svg.appendChild(r);
    var t=document.createElementNS(NS,'text'); t.setAttribute('x',26); t.setAttribute('y',b.y0+2);
    t.setAttribute('fill','#7f93b3'); t.setAttribute('font-size','11'); t.setAttribute('font-weight','700');
    t.textContent=b.name.toUpperCase()+'  ·  '+b.devices+' devices';
    svg.appendChild(t);
  });
  (g.links||[]).forEach(function(l){
    var p=document.createElementNS(NS,'path');
    p.setAttribute('d',l.path); p.setAttribute('fill','none');
    p.setAttribute('stroke', l.spof?'#ff5a52':(l.protected?'#2dd4a7':'#33456a'));
    p.setAttribute('stroke-width', l.spof?2.2:(l.protected?2:1.2));
    if(l.spof) p.setAttribute('stroke-dasharray','6 4');
    var ti=document.createElementNS(NS,'title');
    ti.textContent=(l.src_label||'')+' → '+(l.dst_label||'')+'  ·  '+l.kind+'  ·  confidence '+l.confidence+(l.spof?'  ·  SPOF':'')+(l.protected?'  ·  redundant':'');
    p.appendChild(ti); svg.appendChild(p);
  });
  (g.nodes||[]).forEach(function(n){
    var gr=document.createElementNS(NS,'g'); gr.setAttribute('class','node');
    gr.setAttribute('data-id',n.id); gr.setAttribute('data-sev',n.severity);
    var w=126,h=42,x=n.x-w/2,y=n.y-h/2;
    var r=document.createElementNS(NS,'rect');
    r.setAttribute('x',x); r.setAttribute('y',y); r.setAttribute('width',w); r.setAttribute('height',h); r.setAttribute('rx',9);
    r.setAttribute('fill','#152442'); r.setAttribute('stroke', colorFor(n.severity)); r.setAttribute('stroke-width', n.severity==='critical'||n.severity==='high'?2:1);
    var t1=document.createElementNS(NS,'text'); t1.setAttribute('x',x+9); t1.setAttribute('y',y+17);
    t1.setAttribute('fill','#e6edf7'); t1.setAttribute('font-size','11.5'); t1.setAttribute('font-weight','650');
    t1.textContent=trunc(n.label,20);
    var t2=document.createElementNS(NS,'text'); t2.setAttribute('x',x+9); t2.setAttribute('y',y+31);
    t2.setAttribute('fill','#93a4bd'); t2.setAttribute('font-size','10');
    t2.textContent=trunc((n.ip||'')+' '+(n.type||'')+' '+(n.ports||0)+'p',30);
    var ti=document.createElementNS(NS,'title');
    ti.textContent=n.label+'\n'+n.ip+' · '+n.type+' · '+(n.zone||'')+'\nrisk '+(n.risk||0)+'/10 · '+(n.findings||0)+' findings';
    r.appendChild(ti);
    if(n.findings){
      var c=document.createElementNS(NS,'circle'); c.setAttribute('cx',x+w-13); c.setAttribute('cy',y+12); c.setAttribute('r',9.5);
      c.setAttribute('fill', colorFor(n.severity));
      var ct=document.createElementNS(NS,'text'); ct.setAttribute('x',x+w-13); ct.setAttribute('y',y+16);
      ct.setAttribute('text-anchor','middle'); ct.setAttribute('font-size','10'); ct.setAttribute('font-weight','700'); ct.setAttribute('fill','#0b1220');
      ct.textContent=n.findings;
      gr.appendChild(c); gr.appendChild(ct);
    }
    gr.appendChild(r); gr.appendChild(t1); gr.appendChild(t2);
    gr.addEventListener('click', function(){ select(n.id); });
    svg.appendChild(gr);
  });
  var host=document.getElementById('graph'); host.innerHTML=''; host.appendChild(svg);
  applyFilters();
}
function colorFor(s){ return ({critical:'#ff5a52',high:'#ff9f43',medium:'#ffd166',low:'#5aa9ff',info:'#9aa7bd',none:'#2dd4a7'})[s]||'#5aa9ff'; }
function trunc(s,n){ s=String(s||''); return s.length>n? s.slice(0,n-1)+'…' : s; }

function applyFilters(){
  var q=(state.q||'').toLowerCase();
  var keep=function(sev, hay){
    var sok = !Object.keys(state.sev).filter(function(k){return state.sev[k];}).length || state.sev[sev];
    var qok = !q || (hay||'').toLowerCase().indexOf(q)>-1;
    return sok && qok;
  };
  document.querySelectorAll('#graph .node').forEach(function(g){
    var n=(state.graph.nodes.filter(function(x){return x.id===g.getAttribute('data-id');})[0])||{};
    var ok=keep(g.getAttribute('data-sev'), (n.label||'')+' '+(n.ip||'')+' '+(n.type||'')+' '+(n.zone||''));
    g.classList.toggle('dim', !ok);
  });
  document.querySelectorAll('#ftable tbody tr').forEach(function(tr){
    var ok=keep(tr.getAttribute('data-sev'), tr.getAttribute('data-hay'));
    tr.classList.toggle('muted-row', !ok);
  });
  var shown=[].slice.call(document.querySelectorAll('#ftable tbody tr')).filter(function(t){return !t.classList.contains('muted-row');}).length;
  var badge=document.getElementById('fcount'); if(badge) badge.textContent=shown+' shown';
}

function renderFindings(){
  var tb=document.getElementById('ftable'); tb.innerHTML='';
  state.findings.forEach(function(f){
    var tr=document.createElement('tr');
    tr.className=f.severity; tr.setAttribute('data-sev',f.severity);
    tr.setAttribute('data-hay',(f.rule_id+' '+f.title+' '+f.target+' '+(f.zone||'')+' '+(f.evidence||'')).toLowerCase());
    if(f.target_id) tr.addEventListener('click', function(){ select(f.target_id); });
    tr.innerHTML='<td><span class="chip '+f.severity+'">'+f.severity+'</span></td><td><code>'+esc(f.rule_id)+'</code></td>'+
      '<td>'+esc(f.target)+'</td><td>'+esc(f.title)+'</td><td>'+(f.score||0).toFixed(1)+'</td>';
    tb.appendChild(tr);
  });
}

function renderTables(){
  api('/api/devices').then(function(rows){
    var tb=document.getElementById('dtable'); tb.innerHTML='';
    rows.forEach(function(d){
      var tr=document.createElement('tr');
      tr.className=d.severity||'';
      tr.addEventListener('click', function(){ select(d.id); });
      tr.innerHTML='<td>'+esc(d.hostname||'—')+'</td><td><code>'+esc(d.ip||'')+'</code></td><td>'+esc(d.type)+'</td>'+
        '<td>'+esc(d.os)+'</td><td>'+esc(d.zone||'')+'</td><td>'+esc(d.ports)+'</td><td>'+esc(d.criticality)+'</td>'+
        '<td>'+(d.risk||0).toFixed(1)+'</td><td>'+esc(d.findings)+'</td>';
      tb.appendChild(tr);
    });
  });
  api('/api/zones').then(function(rows){
    var tb=document.getElementById('ztable'); tb.innerHTML='';
    rows.forEach(function(z){
      var tr=document.createElement('tr');
      tr.innerHTML='<td><b>'+esc(z.name)+'</b></td><td>'+esc(z.trust)+'</td><td>'+esc(z.devices)+'</td>'+
        '<td>'+esc((z.cidrs||[]).join(', ')||'—')+'</td><td>'+esc((z.vlans||[]).join(', ')||'—')+'</td>'+
        '<td>'+(z.enforced?'<span class="chip ok">enforced</span>':'<span class="chip medium">not enforced</span>')+'</td>';
      tb.appendChild(tr);
    });
  });
  api('/api/links').then(function(rows){
    var tb=document.getElementById('ltable'); tb.innerHTML='';
    rows.forEach(function(l){
      var tr=document.createElement('tr');
      tr.innerHTML='<td>'+esc(l.src)+'</td><td>'+esc(l.dst)+'</td><td>'+esc(l.kind)+'</td><td>'+esc(l.speed||'—')+'</td>'+
        '<td>'+esc(l.source)+'</td><td>'+esc(l.confidence)+'</td><td>'+esc(l.notes)+'</td>';
      tb.appendChild(tr);
    });
  });
}

function select(id){
  state.sel=id;
  api('/api/device/'+encodeURIComponent(id)).then(function(d){
    var host=document.getElementById('drawer'); host.innerHTML='';
    host.appendChild(el('h3','',esc(d.label||d.id)));
    var box=el('div','');
    [['type',d.type],['role',d.role],['address',d.ip],['mac',d.mac],['zone',d.zone],['trust',d.trust],
     ['vendor/model',d.model? (d.vendor||'')+' '+d.model : d.vendor],['os',(d.os||'')+(d.os_eol?'  ·  EOL '+d.os_eol:'')],
     ['criticality',d.criticality],['risk',(d.risk||0).toFixed? (d.risk||0).toFixed(1):d.risk],
     ['documented', d.documented?'yes':'NO'],['exposed to WAN', d.exposed?'yes':'no'],
     ['snmp', d.snmp_readable?'readable':'none'],['uptime', d.uptime],['sources',(d.sources||[]).join(', ')]]
    .forEach(function(f){ if(f[1]===undefined||f[1]===null||f[1]==='') return; var row=el('div','fld'); row.innerHTML='<b>'+esc(f[0])+'</b><span>'+esc(f[1])+'</span>'; box.appendChild(row); });
    host.appendChild(box);
    host.appendChild(el('h4','','Services'));
    var sv=el('div',''); sv.innerHTML='<table><thead><tr><th>Port</th><th>Name</th><th>Product</th><th>Enc</th></tr></thead><tbody>'+
      (d.services||[]).map(function(s){ return '<tr><td><code>'+esc(s.port)+'/'+esc(s.protocol)+'</code></td><td>'+esc(s.name||'')+
        '</td><td>'+esc([s.product,s.version].filter(Boolean).join(' '))+'</td><td>'+(s.encryption==='none'?'<span class="chip medium">clear</span>':esc(s.encryption||''))+
        (s.cert? ' <span class="chip ghost" title="'+esc(s.cert)+'">cert</span>':'')+'</td></tr>'; }).join('')+'</tbody></table>';
    host.appendChild(sv);
    host.appendChild(el('h4','','Findings ('+(d.findings||[]).length+')'));
    var fw=el('div','');
    (d.findings||[]).forEach(function(f){
      var n=el('div','finding '+f.severity);
      n.innerHTML='<h4><span class="chip '+f.severity+'">'+f.severity+'</span> '+esc(f.title)+' <code>'+esc(f.rule_id)+'</code></h4>'+
        '<ul>'+(f.evidence||[]).map(function(e){return '<li>'+esc(e)+'</li>';}).join('')+'</ul>'+
        (f.remediation? '<p><b>Fix:</b> '+esc(f.remediation)+'</p>':'')+
        (f.refs? '<p class="note">'+esc(f.refs)+'</p>':'');
      fw.appendChild(n);
    });
    if(!(d.findings||[]).length) fw.appendChild(el('div','note','No open findings on this device.'));
    host.appendChild(fw);
  });
}

function tab(name){
  document.querySelectorAll('[data-tab]').forEach(function(p){ p.style.display = (p.getAttribute('data-tab')===name)?'':'none'; });
  document.querySelectorAll('.tabs button').forEach(function(b){ b.setAttribute('aria-selected', b.getAttribute('data-show')===name?'true':'false'); });
}

function runScan(){
  var btn=document.getElementById('scan'); btn.disabled=true; btn.textContent='running…';
  var mode=document.getElementById('mode').value;
  var body={mode:mode};
  if(mode==='lab'){ body.size=document.getElementById('labsize').value; }
  else { body.targets=document.getElementById('targets').value.split(/[\s,]+/).filter(Boolean); body.confirm=!!document.getElementById('confirm').checked; }
  var bar=document.getElementById('prog'); bar.style.display=''; bar.innerHTML='<progress/>';
  api('/api/scan',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}).then(function(j){
    var poll=function(){
      return api('/api/scan/'+j.job).then(function(s){
        var pr=bar.querySelector('progress'); if(pr){ pr.max=s.total||1; pr.value=s.done||0; }
        bar.insertAdjacentHTML('beforeend',''); bar.setAttribute('data-note', s.stage||'');
        var note=document.getElementById('prognote'); if(!note){ note=el('div','note',''); note.id='prognote'; bar.appendChild(note); }
        note.textContent=(s.stage||'')+' — '+(s.message||'');
        if(s.state==='done'){ btn.disabled=false; btn.textContent='run scan'; return loadAll(); }
        if(s.state==='error'){ btn.disabled=false; btn.textContent='run scan'; note.textContent='error: '+(s.error||'failed'); return; }
        return new Promise(function(r){ setTimeout(r,700); }).then(poll);
      });
    };
    return poll();
  });
}

document.addEventListener('DOMContentLoaded', function(){
  ['critical','high','medium','low'].forEach(function(s){
    var b=document.querySelector('[data-sev-f="'+s+'"]');
    if(b) b.addEventListener('click', function(){ state.sev[s]=!state.sev[s]; b.setAttribute('aria-pressed', state.sev[s]?'true':'false'); applyFilters(); });
  });
  var q=document.getElementById('q'); if(q) q.addEventListener('input', function(){ state.q=q.value; applyFilters(); });
  document.querySelectorAll('.tabs button').forEach(function(b){ b.addEventListener('click', function(){ tab(b.getAttribute('data-show')); }); });
  var s=document.getElementById('scan'); if(s) s.addEventListener('click', runScan);
  document.querySelectorAll('[data-sort]').forEach(function(th){ th.addEventListener('click', function(){
    var t=th.closest('table'), tb=t.tBodies[0], rows=[].slice.call(tb.rows), i=th.cellIndex, dir=th.getAttribute('data-dir')==='asc'?'desc':'asc';
    th.setAttribute('data-dir',dir);
    rows.sort(function(a,b){ var x=a.cells[i].innerText.trim(), y=b.cells[i].innerText.trim(), nx=parseFloat(x), ny=parseFloat(y);
      var c=(!isNaN(nx)&&!isNaN(ny))?nx-ny:x.localeCompare(y); return dir==='asc'?c:-c; });
    rows.forEach(function(r){ tb.appendChild(r); });
  });});
  loadAll().then(function(){ tab('topology'); });
});
"""


def render_app(*, title: str = "NetMap", version: str = __version__, live: bool = True) -> str:
    """Return the dashboard HTML.

    `live=False` hides the run-scan control: used when the server is attached to
    a read-only snapshot file so the UI cannot promise an action it will refuse.
    """
    scan_control = (
        "<div class='row'>"
        "<select id='mode'><option value='lab'>lab (synthetic)</option><option value='live'>live</option></select>"
        "<select id='labsize'><option value='small'>small</option><option value='medium' selected>medium</option><option value='large'>large</option></select>"
        "<input class='grow' id='targets' placeholder='targets for live mode, e.g. 10.0.0.0/24'>"
        "<label class='note'><input type='checkbox' id='confirm'> I am authorized to scan these systems</label>"
        "<button id='scan' class='primary'>run scan</button>"
        "</div><div id='prog' style='display:none'></div>"
    ) if live else "<div class='note'>read-only view of the attached snapshot</div>"
    head = (
        "<header><h1>NetMap <span class='pill'>" + esc(version) + "</span> <span class='pill' id='meta'></span></h1>"
        "<div class='row'><div class='scorebox' id='score'></div>" + scan_control + "</div></header>"
    )
    body = (
        "<main><div id='body'><div class='kpis' id='kpis'></div>"
        "<section class='panel'><h2>Topology"
        "<div class='row'>"
        "<button data-sev-f='critical' aria-pressed='false'>critical</button>"
        "<button data-sev-f='high' aria-pressed='false'>high</button>"
        "<button data-sev-f='medium' aria-pressed='false'>medium</button>"
        "<button data-sev-f='low' aria-pressed='false'>low</button>"
        "<input id='q' placeholder='search host / ip / vlan' size='22'>"
        "<a href='/api/report.md' download>report.md</a> <a href='/api/report.html' download>report.html</a> "
        "<a href='/api/report.sarif' download>sarif</a> <a href='/api/report.csv' download>csv</a> "
        "<a href='/api/snapshot' download>snapshot.json</a>"
        "</div></h2>"
        "<div class='tabs'><button data-show='topology' aria-selected='true'>map</button>"
        "<button data-show='findings' aria-selected='false'>findings</button>"
        "<button data-show='devices' aria-selected='false'>devices</button>"
        "<button data-show='zones' aria-selected='false'>zones</button>"
        "<button data-show='links' aria-selected='false'>links</button></div>"
        "<div data-tab='topology' class='svgwrap' id='graph'></div>"
        "<div data-tab='findings' style='display:none'><div class='scroll'><table><thead><tr>"
        "<th data-sort>Sev</th><th data-sort>Rule</th><th data-sort>Target</th><th data-sort>Finding</th><th data-sort>Score</th>"
        "</tr></thead><tbody id='ftable'></tbody></table></div></div>"
        "<div data-tab='devices' style='display:none'><div class='scroll'><table><thead><tr>"
        "<th data-sort>Host</th><th data-sort>IP</th><th data-sort>Type</th><th data-sort>OS</th><th data-sort>Zone</th>"
        "<th data-sort>Ports</th><th data-sort>Crit</th><th data-sort>Risk</th><th data-sort>Findings</th>"
        "</tr></thead><tbody id='dtable'></tbody></table></div></div>"
        "<div data-tab='zones' style='display:none'><div class='scroll'><table><thead><tr>"
        "<th data-sort>Zone</th><th data-sort>Trust</th><th data-sort>Devices</th><th data-sort>CIDRs</th><th data-sort>VLANs</th><th>Segmentation</th>"
        "</tr></thead><tbody id='ztable'></tbody></table></div></div>"
        "<div data-tab='links' style='display:none'><div class='scroll'><table><thead><tr>"
        "<th data-sort>From</th><th data-sort>To</th><th data-sort>Kind</th><th data-sort>Speed</th><th data-sort>Source</th><th data-sort>Conf</th><th>Notes</th>"
        "</tr></thead><tbody id='ltable'></tbody></table></div></div>"
        "<div id='prog2'></div>"
        "</section></div>"
        "<aside class='panel drawer'><h2>Detail <span class='chip ghost'>click anything</span></h2>"
        "<div class='body' id='drawer'><div class='note'>Select a device, a finding row or a link to inspect it.</div></div>"
        "</aside></main>"
        f"<footer>NetMap {esc(version)} · findings are advisory — confirm on the device before changing config</footer>"
    )
    return (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{esc(title)}</title><style>{_STYLE}</style></head><body>"
        f"{head}{body}<script>{_SCRIPT}</script></body></html>"
    )


__all__ = ["render_app"]
