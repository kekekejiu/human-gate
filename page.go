package main

import "strings"

func renderGatePage() string {
	page := strings.ReplaceAll(gatePageHTML, "__SUPPORT_MARKUP__", supportMarkup())
	return strings.ReplaceAll(page, "__SUPPORT_EMBED__", supportEmbedMarkup())
}

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
.support{margin-top:18px;padding-top:14px;border-top:1px solid #e5e7eb;display:flex;flex-wrap:wrap;align-items:center;justify-content:center;gap:8px 12px;color:#6b7280;font-size:12px;text-align:center}
.support a{color:#2563eb;text-decoration:none}
.support-primary{display:inline-block;padding:7px 12px;border-radius:8px;background:#eff6ff;font-weight:600}
.support-note{width:100%;color:#374151}
.support small{display:block;width:100%;color:#9ca3af;line-height:1.5}
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
  __SUPPORT_MARKUP__
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
var cur={id:'',tileWidth:0,tileHeight:0,tileY:0};
var dragging=false,startX=0,startRatio=0,ratio=0,maxHandle=0;
var pointerTravel=0,startPointerTravel=0;
var activePointerId=null,submitting=false;

function clamp(v,min,max){return Math.max(min,Math.min(max,v))}
function metrics(){
  var displayW=master.clientWidth||1;
  var naturalW=master.naturalWidth||displayW;
  var scale=displayW/naturalW;
  var tileW=cur.tileWidth*scale,tileH=cur.tileHeight*scale;
  return {displayW:displayW,naturalW:naturalW,scale:scale,tileW:tileW,tileH:tileH,
    tileTravel:Math.max(0,displayW-tileW),answerTravel:Math.max(0,naturalW-cur.tileWidth)};
}
function applyPosition(){
  var m=metrics(),trackRect=track.getBoundingClientRect();
  var handleRect=handle.getBoundingClientRect();
  maxHandle=Math.max(0,track.clientWidth-handle.offsetWidth);
  pointerTravel=Math.max(0,trackRect.width-handleRect.width);
  ratio=clamp(ratio,0,1);
  var handleX=ratio*maxHandle;
  handle.style.transform='translate3d('+handleX+'px,0,0)';
  fill.style.width=(handleX+handle.offsetWidth/2)+'px';
  tile.style.width=m.tileW+'px';
  tile.style.height=m.tileH+'px';
  tile.style.top=(cur.tileY*m.scale)+'px';
  tile.style.transform='translate3d('+(ratio*m.tileTravel)+'px,0,0)';
}
function safeNext(){
  try{
    var p=new URLSearchParams(location.search).get('next')||'/';
    if(p.charAt(0)==='/'&&p.charAt(1)!=='/') return p;
  }catch(e){}
  return '/';
}
function reset(){
  ratio=0;dragging=false;activePointerId=null;submitting=false;
  handle.classList.remove('grab');
  tip.style.display='';
  applyPosition();
}
function load(){
  loading.style.display='flex';
  loading.textContent='加载中...';
  statusEl.textContent='';statusEl.className='status';
  fetch('/__gate/new',{cache:'no-store'}).then(function(r){
    if(!r.ok)throw new Error('challenge '+r.status);
    return r.json();
  }).then(function(d){
    cur.id=d.id;cur.tileWidth=d.tile_width;cur.tileHeight=d.tile_height;cur.tileY=d.tile_y;
    master.onload=function(){
      requestAnimationFrame(function(){loading.style.display='none';reset();});
    };
    master.src=d.master;
    tile.src=d.tile;
  }).catch(function(){loading.textContent='加载失败，请刷新';});
}
function start(e){
  if(!cur.id||dragging||submitting)return;
  applyPosition();
  dragging=true;activePointerId=e.pointerId;
  startX=e.clientX;startRatio=ratio;startPointerTravel=pointerTravel;
  if(handle.setPointerCapture)handle.setPointerCapture(e.pointerId);
  handle.classList.add('grab');
  tip.style.display='none';
  e.preventDefault();
}
function move(e){
  if(!dragging||e.pointerId!==activePointerId)return;
  ratio=clamp(startRatio+(e.clientX-startX)/(maxHandle||1),0,1);
  applyPosition();
  e.preventDefault();
}
function end(e){
  if(!dragging||e.pointerId!==activePointerId||submitting)return;
  dragging=false;submitting=true;
  if(handle.hasPointerCapture&&handle.hasPointerCapture(e.pointerId))handle.releasePointerCapture(e.pointerId);
  activePointerId=null;handle.classList.remove('grab');
  e.preventDefault();
  var m=metrics();
  var ansX=Math.round(clamp(ratio,0,1)*m.answerTravel);
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
function cancel(e){
  if(!dragging||e.pointerId!==activePointerId)return;
  dragging=false;activePointerId=null;ratio=0;
  handle.classList.remove('grab');
  tip.style.display='';
  applyPosition();
  if(e.preventDefault)e.preventDefault();
}
handle.addEventListener('pointerdown',start);
handle.addEventListener('pointermove',move);
handle.addEventListener('pointerup',end);
handle.addEventListener('pointercancel',cancel);
handle.addEventListener('lostpointercapture',cancel);
window.addEventListener('resize',function(){if(cur.id)requestAnimationFrame(applyPosition)});
if(window.visualViewport){
  window.visualViewport.addEventListener('resize',function(){if(cur.id)requestAnimationFrame(applyPosition)});
}
window.addEventListener('orientationchange',function(){setTimeout(applyPosition,150)});
load();
})();
</script>
__SUPPORT_EMBED__
</body>
</html>`
