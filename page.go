package main

const gatePageHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<meta name="robots" content="noindex,nofollow">
<title>安全验证</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#0f2027,#203a43,#2c5364);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif}
.card{width:340px;max-width:92vw;background:#fff;border-radius:16px;padding:24px;box-shadow:0 20px 50px rgba(0,0,0,.35)}
h1{margin:0 0 6px;font-size:19px;color:#1f2937;text-align:center}
.sub{margin:0 0 16px;font-size:13px;color:#6b7280;text-align:center}
.cap{position:relative;width:100%;border-radius:10px;overflow:hidden;background:#f3f4f6;min-height:160px}
.master{display:block;width:100%;height:auto}
.tile{position:absolute;top:0;left:0;height:auto;will-change:transform}
.loading{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:#9ca3af;font-size:13px}
.track{position:relative;margin-top:16px;height:44px;background:#eef1f5;border-radius:22px;user-select:none}
.track-fill{position:absolute;left:0;top:0;height:100%;width:0;background:linear-gradient(90deg,#34d399,#10b981);border-radius:22px}
.handle{position:absolute;left:0;top:0;width:44px;height:44px;border-radius:50%;background:#fff;box-shadow:0 2px 8px rgba(0,0,0,.2);display:flex;align-items:center;justify-content:center;cursor:grab;color:#10b981;font-size:18px;font-weight:700;touch-action:none}
.handle.grab{cursor:grabbing}
.track-tip{position:absolute;width:100%;text-align:center;line-height:44px;color:#9ca3af;font-size:13px;pointer-events:none}
.status{margin-top:12px;min-height:18px;font-size:13px;text-align:center}
.status.ok{color:#10b981}
.status.err{color:#ef4444}
</style>
</head>
<body>
<div class="card">
  <h1>请完成安全验证</h1>
  <p class="sub">拖动下方滑块，使拼图对齐缺口</p>
  <div class="cap" id="cap">
    <img class="master" id="master" alt="">
    <img class="tile" id="tile" alt="">
    <div class="loading" id="loading">加载中...</div>
  </div>
  <div class="track" id="track">
    <div class="track-fill" id="fill"></div>
    <div class="handle" id="handle">&#8594;</div>
    <span class="track-tip" id="tip">向右拖动滑块</span>
  </div>
  <div class="status" id="status"></div>
</div>
<script>
(function(){
var master=document.getElementById('master');
var tile=document.getElementById('tile');
var track=document.getElementById('track');
var handle=document.getElementById('handle');
var fill=document.getElementById('fill');
var tip=document.getElementById('tip');
var statusEl=document.getElementById('status');
var loading=document.getElementById('loading');
var cur={id:'',tileWidth:0};
var dragging=false,startX=0,handleX=0,maxHandle=0;

function safeNext(){
  try{
    var p=new URLSearchParams(location.search).get('next')||'/';
    if(p.charAt(0)==='/'&&p.charAt(1)!=='/') return p;
  }catch(e){}
  return '/';
}
function reset(){
  handleX=0;dragging=false;
  handle.style.transform='translateX(0)';
  tile.style.transform='translateX(0)';
  fill.style.width='0';
  handle.classList.remove('grab');
}
function load(){
  loading.style.display='flex';
  statusEl.textContent='';statusEl.className='status';
  fetch('/__gate/new',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
    cur.id=d.id;cur.tileWidth=d.tile_width;
    master.onload=function(){
      var wd=master.clientWidth,nw=master.naturalWidth||wd;
      var tdw=d.tile_width*(wd/nw);
      tile.style.width=tdw+'px';
      tile.style.top=d.tile_y+'px';
      maxHandle=track.clientWidth-handle.clientWidth;
      loading.style.display='none';reset();
    };
    master.src=d.master;
    tile.src=d.tile;
  }).catch(function(){loading.textContent='加载失败，请刷新';});
}
function pointerX(e){return e.touches&&e.touches.length?e.touches[0].clientX:e.clientX}
function start(e){
  if(!cur.id)return;
  dragging=true;startX=pointerX(e);handle.classList.add('grab');
  tip.style.display='none';
  e.preventDefault();
}
function move(e){
  if(!dragging)return;
  var dx=pointerX(e)-startX;
  handleX=Math.max(0,Math.min(maxHandle,dx));
  handle.style.transform='translateX('+handleX+'px)';
  fill.style.width=(handleX+handle.clientWidth/2)+'px';
  var wd=master.clientWidth,nw=master.naturalWidth||wd;
  tile.style.transform='translateX('+(handleX*(nw/wd))+'px)';
}
function end(){
  if(!dragging)return;
  dragging=false;handle.classList.remove('grab');
  var wd=master.clientWidth,nw=master.naturalWidth||wd;
  var ansX=Math.round(handleX*(nw/wd));
  fetch('/__gate/verify',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id:cur.id,x:ansX,y:0})}).then(function(r){return r.json()}).then(function(d){
    if(d.ok){
      statusEl.textContent='验证通过，正在跳转...';statusEl.className='status ok';
      setTimeout(function(){location.replace(safeNext())},500);
    }else{
      statusEl.textContent='验证失败，请重试';statusEl.className='status err';
      setTimeout(load,700);
    }
  }).catch(function(){statusEl.textContent='网络错误，请重试';statusEl.className='status err';setTimeout(load,700);});
}
handle.addEventListener('mousedown',start);
window.addEventListener('mousemove',move);
window.addEventListener('mouseup',end);
handle.addEventListener('touchstart',start,{passive:false});
window.addEventListener('touchmove',move,{passive:false});
window.addEventListener('touchend',end);
load();
})();
</script>
</body>
</html>`

