package main

const adminLoginHTML = `<!doctype html><html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>分析面板登录</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f172a;font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
.box{width:320px;background:#1e293b;border-radius:14px;padding:28px;box-shadow:0 20px 50px rgba(0,0,0,.4)}
h1{margin:0 0 18px;font-size:18px;color:#e2e8f0;text-align:center}
label{display:block;font-size:13px;color:#94a3b8;margin:12px 0 6px}
input{width:100%;box-sizing:border-box;height:40px;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;padding:0 12px;font-size:14px}
button{width:100%;margin-top:18px;height:40px;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-size:15px;cursor:pointer}
button:hover{background:#2563eb}
</style></head><body>
<form class="box" method="post" action="/__gate/admin/login">
<h1>访客分析面板</h1>
<label>用户名</label><input name="username" autocomplete="username" autofocus>
<label>密码</label><input name="password" type="password" autocomplete="current-password">
<button type="submit">登录</button>
</form></body></html>`

const adminPageHTML = `<!doctype html><html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>访客分析面板</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0f172a;color:#e2e8f0;font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;font-size:14px}
header{display:flex;align-items:center;gap:12px;padding:16px 22px;background:#1e293b;position:sticky;top:0;z-index:5}
header h1{font-size:18px;margin:0;flex:0 0 auto}
header select,header button{height:34px;border-radius:7px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;padding:0 12px;cursor:pointer}
header button{background:#3b82f6;border:0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;padding:18px 22px}
.card{background:#1e293b;border-radius:12px;padding:16px}
.card .n{font-size:26px;font-weight:700}
.card .l{font-size:13px;color:#94a3b8;margin-top:4px}
.card.danger .n{color:#ef4444}.card.suspect .n{color:#f59e0b}.card.idc .n{color:#a78bfa}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;padding:0 22px}
.panel{background:#1e293b;border-radius:12px;padding:16px;margin-bottom:14px}
.panel h2{font-size:15px;margin:0 0 12px}
.bar{display:flex;align-items:center;gap:8px;margin:6px 0;font-size:13px}
.bar .k{width:120px;color:#cbd5e1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar .t{flex:1;height:8px;background:#0f172a;border-radius:4px;overflow:hidden}
.bar .f{height:100%;background:#3b82f6}
.bar .c{width:50px;text-align:right;color:#94a3b8}
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #334155;white-space:nowrap}
th{color:#94a3b8;font-weight:500}
td.ua{max-width:220px;overflow:hidden;text-overflow:ellipsis}
.tag{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11px}
.tag.ok{background:#14532d;color:#86efac}.tag.suspect{background:#78350f;color:#fcd34d}.tag.danger{background:#7f1d1d;color:#fca5a5}
.tag.idc{background:#4c1d95;color:#c4b5fd}.tag.carrier{background:#1e3a8a;color:#93c5fd}
.filters{font-size:13px;font-weight:400;margin-left:10px}
.filters a{color:#94a3b8;text-decoration:none;margin:0 6px;padding:2px 8px;border-radius:5px}
.filters a.active{background:#3b82f6;color:#fff}
</style>
</head><body>
<header><h1>访客分析面板</h1>
<select id="hours">
<option value="1">最近1小时</option>
<option value="24" selected>最近24小时</option>
<option value="168">最近7天</option>
<option value="720">最近30天</option>
</select>
<button onclick="loadAll()">刷新</button>
</header>
<section class="cards" id="cards"></section>
<section class="grid">
<div class="panel"><h2>运营商分布</h2><div id="by_isp"></div></div>
<div class="panel"><h2>IP类型分布</h2><div id="by_type"></div></div>
<div class="panel"><h2>国家/地区</h2><div id="by_country"></div></div>
<div class="panel"><h2>高频IP Top30</h2><div id="top_ip"></div></div>
</section>
<section class="panel">
<h2>跨站联防（观察模式）</h2>
<div id="policy_status" style="color:#94a3b8;margin-bottom:10px">加载中...</div>
<div class="tablewrap"><table><thead><tr><th>候选IP</th><th>首次</th><th>最近</th><th>次数</th><th>站点</th><th>原因</th></tr></thead><tbody id="policy_candidates"></tbody></table></div>
<h2 style="margin-top:18px">最近观察命中</h2>
<div class="tablewrap"><table><thead><tr><th>时间</th><th>IP</th><th>站点</th><th>版本</th><th>模式</th><th>拟执行动作</th></tr></thead><tbody id="policy_hits"></tbody></table></div>
</section>
<section class="panel">
<h2>最近访问 <span class="filters">
<a href="#" data-r="" class="active">全部</a>
<a href="#" data-r="suspect">可疑</a>
<a href="#" data-r="danger">高危</a>
</span></h2>
<div class="tablewrap"><table id="recent"><thead><tr>
<th>时间</th><th>IP</th><th>类型</th><th>运营商</th><th>地区</th><th>ASN组织</th><th>UA</th><th>状态</th><th>风险</th>
</tr></thead><tbody></tbody></table></div>
</section>
<script>
var curRisk="";
function hours(){return document.getElementById('hours').value}
function api(p){return fetch('/__gate/admin/api/'+p,{cache:'no-store'}).then(function(r){return r.json()})}
function esc(s){var d=document.createElement('div');d.textContent=s==null?'':String(s);return d.innerHTML}
function fmtTime(ts){var d=new Date(ts*1000);return d.toLocaleString('zh-CN',{hour12:false})}

function loadSummary(){
  api('summary?hours='+hours()).then(function(s){
    var c=document.getElementById('cards');
    c.innerHTML=
      card('',s.total,'访问次数')+
      card('',s.unique_ip,'独立IP')+
      card('suspect',s.suspect,'可疑')+
      card('danger',s.danger,'高危')+
      card('idc',s.idc,'机房IP访问');
  });
}
function card(cls,n,l){return '<div class="card '+cls+'"><div class="n">'+(n||0)+'</div><div class="l">'+l+'</div></div>'}

function loadBars(id,p){
  api(p+'?hours='+hours()).then(function(rows){
    rows=rows||[];var max=1;rows.forEach(function(x){if(x.count>max)max=x.count});
    document.getElementById(id).innerHTML=rows.map(function(x){
      var w=Math.round(x.count/max*100);
      return '<div class="bar"><span class="k">'+esc(x.key||'(空)')+'</span><span class="t"><span class="f" style="width:'+w+'%"></span></span><span class="c">'+x.count+'</span></div>';
    }).join('')||'<div style="color:#64748b">暂无数据</div>';
  });
}

function loadRecent(){
  api('recent?limit=200&risk='+curRisk).then(function(rows){
    rows=rows||[];
    var tb=document.querySelector('#recent tbody');
    tb.innerHTML=rows.map(function(v){
      var typeTag=v.ip_type==='idc'?'<span class="tag idc">机房</span>':(v.ip_type==='carrier'?'<span class="tag carrier">宽带</span>':esc(v.ip_type));
      var st=v.passed==1?'<span class="tag ok">已通过</span>':'待验证';
      var rk='<span class="tag '+v.risk_level+'">'+v.risk_level+'</span>';
      var region=[v.province,v.city].filter(Boolean).join(' ');
      return '<tr><td>'+fmtTime(v.ts)+'</td><td>'+esc(v.ip)+'</td><td>'+typeTag+'</td><td>'+esc(v.isp)+'</td><td>'+esc(v.country+' '+region)+'</td><td>'+esc(v.asn_org)+'</td><td class="ua" title="'+esc(v.ua)+'">'+esc(v.ua)+'</td><td>'+st+'</td><td title="'+esc(v.risk_tags)+'">'+rk+'</td></tr>';
    }).join('')||'<tr><td colspan="9" style="color:#64748b">暂无数据</td></tr>';
  });
}

function loadPolicy(){
  api('policy_status').then(function(s){
    document.getElementById('policy_status').innerHTML='模式：<b>'+esc(s.mode)+'</b>　版本：'+esc(s.version)+'　候选：'+esc(s.candidate_count)+'　白名单：'+esc(s.allow_count)+'　拟执行：'+esc(s.action);
  });
  api('policy_candidates').then(function(rows){
    rows=rows||[];
    document.getElementById('policy_candidates').innerHTML=rows.map(function(v){
      return '<tr><td>'+esc(v.ip)+'</td><td>'+fmtTime(v.first_seen)+'</td><td>'+fmtTime(v.last_seen)+'</td><td>'+v.hit_count+'</td><td>'+esc(v.sites)+'</td><td>'+esc(v.reasons)+'</td></tr>';
    }).join('')||'<tr><td colspan="6" style="color:#64748b">暂无候选</td></tr>';
  });
  api('policy_hits?limit=100').then(function(rows){
    rows=rows||[];
    document.getElementById('policy_hits').innerHTML=rows.map(function(v){
      return '<tr><td>'+fmtTime(v.ts)+'</td><td>'+esc(v.ip)+'</td><td>'+esc(v.site)+'</td><td>'+v.version+'</td><td>'+esc(v.mode)+'</td><td>'+esc(v.action)+'</td></tr>';
    }).join('')||'<tr><td colspan="6" style="color:#64748b">暂无观察命中</td></tr>';
  });
}

function loadAll(){loadSummary();loadBars('by_isp','by_isp');loadBars('by_type','by_type');loadBars('by_country','by_country');loadBars('top_ip','top_ip');loadRecent();loadPolicy();}

document.querySelectorAll('.filters a').forEach(function(a){
  a.addEventListener('click',function(e){
    e.preventDefault();
    document.querySelectorAll('.filters a').forEach(function(x){x.classList.remove('active')});
    a.classList.add('active');curRisk=a.dataset.r;loadRecent();
  });
});
document.getElementById('hours').addEventListener('change',loadAll);
loadAll();
setInterval(loadAll,30000);
</script>
</body></html>`
