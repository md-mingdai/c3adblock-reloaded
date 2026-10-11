#pragma once
// Dashboard HTML for the C3 AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).
// No emoji, no external assets (fonts/CDN/images) — everything is inline and
// system-font so the page renders fully offline on the device.

const char PAGE[] PROGMEM = R"HTML(<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="theme-color" content="#f5f7fa">
<title>C3 广告拦截器</title>
<style>
:root{
  --bg:#f5f7fa; --surface:#ffffff; --surface-2:#eef2f6; --line:#d9e1e9; --line-soft:#e9eef3;
  --text:#17202d; --muted:#5b6a7c; --faint:#96a3b2;
  --accent:#0b7ea6; --accent-ink:#ffffff;
  --good:#15803d; --warn:#b45309; --bad:#dc2626;
  --sans:"PingFang SC","Microsoft YaHei","Noto Sans CJK SC","Source Han Sans SC",system-ui,-apple-system,"Segoe UI",sans-serif;
  --mono:ui-monospace,"SF Mono","Cascadia Mono","JetBrains Mono",Consolas,"Liberation Mono",monospace;
  color-scheme:light;
}
*{box-sizing:border-box}
[hidden]{display:none!important}
html,body{margin:0;padding:0}
body{
  font:15px/1.55 var(--sans); background:var(--bg); color:var(--text);
  -webkit-font-smoothing:antialiased; text-rendering:optimizeLegibility;
}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.mono{font-family:var(--mono);font-size:.92em;letter-spacing:.01em}

/* ---- top bar ---- */
.topbar{
  display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;
  padding:14px 20px;border-bottom:1px solid var(--line);
  background:rgba(255,255,255,.9);position:sticky;top:0;z-index:10;backdrop-filter:blur(8px);
}
.brand{display:flex;align-items:center;gap:10px}
.logo{display:inline-block;vertical-align:middle;fill:var(--accent);flex:none}
.brand .name{font-weight:700;font-size:16px;letter-spacing:.01em}
.brand .host{font-family:var(--mono);font-size:12.5px;color:var(--muted)}
.live{display:flex;align-items:center;gap:8px;font-size:13.5px;color:var(--text)}
.dot{width:9px;height:9px;border-radius:50%;background:var(--faint);display:inline-block;flex:none}
.dot.on{background:var(--good);animation:pulse 2.4s infinite}
.dot.paused{background:var(--warn)}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(21,128,61,.4)}70%{box-shadow:0 0 0 7px rgba(21,128,61,0)}100%{box-shadow:0 0 0 0 rgba(21,128,61,0)}}
@media (prefers-reduced-motion:reduce){.dot.on{animation:none}}

.wrap{max-width:1040px;margin:0 auto;padding:22px 20px 64px}

/* ---- warning banner ---- */
.warn{
  display:flex;gap:10px;align-items:flex-start;
  background:rgba(220,38,38,.07);border:1px solid rgba(220,38,38,.3);color:#b91c1c;
  border-radius:10px;padding:12px 15px;margin-bottom:18px;font-size:13.5px;line-height:1.5;
}
.warn-ico{flex:none;margin-top:1px}
.warn code{background:rgba(220,38,38,.1);padding:1px 6px;border-radius:4px;font-family:var(--mono)}

/* ---- hero instrument ---- */
.hero{
  display:grid;grid-template-columns:1fr auto;gap:8px 24px;
  background:linear-gradient(180deg,var(--surface),#fbfcfe);
  border:1px solid var(--line);border-radius:14px;padding:22px 24px;margin-bottom:18px;
}
.hero-main{grid-column:1/-1}
.hero-label{font-size:12.5px;color:var(--muted);margin-bottom:2px}
.hero-num{
  font-family:var(--mono);font-weight:650;font-size:clamp(40px,9vw,64px);line-height:1;
  color:var(--accent);font-variant-numeric:tabular-nums;letter-spacing:-.01em;
}
.hero-num.small{font-size:clamp(24px,5vw,34px);color:var(--text);font-weight:550}
.hero-ctrl{display:flex;align-items:center;gap:8px;flex-wrap:wrap;align-self:end;justify-content:flex-end}
@media (min-width:640px){
  .hero{grid-template-columns:auto 1fr;grid-template-rows:auto auto}
  .hero-main{grid-column:1;grid-row:1/-1;min-width:300px;border-right:1px solid var(--line-soft);padding-right:24px}
  .hero-side{align-self:end}
  .hero-ctrl{grid-column:2;align-self:start;justify-content:flex-start}
}

/* ---- stat rail ---- */
.stats{display:grid;grid-template-columns:repeat(2,1fr);gap:1px;background:var(--line-soft);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-bottom:26px}
.stat{background:var(--surface);padding:14px 16px;display:flex;flex-direction:column;gap:2px}
.stat-v{font-family:var(--mono);font-size:19px;font-weight:600;font-variant-numeric:tabular-nums}
.stat-l{font-size:12px;color:var(--muted)}
@media (min-width:720px){.stats{grid-template-columns:repeat(3,1fr)}}
@media (min-width:960px){.stats{grid-template-columns:repeat(6,1fr)}}

/* ---- sections ---- */
section{margin-bottom:30px}
h2{
  font-size:13px;font-weight:600;color:var(--muted);letter-spacing:.02em;
  margin:0 0 10px;padding-bottom:8px;border-bottom:1px solid var(--line-soft);
  display:flex;align-items:center;gap:8px;
}
h2::before{content:"";width:3px;height:14px;background:var(--accent);border-radius:2px}

.tablewrap{border:1px solid var(--line);border-radius:12px;overflow:auto}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{padding:10px 14px;text-align:left;white-space:nowrap}
thead th{background:var(--surface-2);color:var(--muted);font-weight:500;font-size:12px;border-bottom:1px solid var(--line)}
tbody td{border-top:1px solid var(--line-soft)}
tbody tr{transition:background .12s}
tbody tr:hover{background:var(--surface-2)}
td.num{font-family:var(--mono);font-variant-numeric:tabular-nums}
td.blocked{color:var(--bad)}
td.allowed{color:var(--good)}
td.act{text-align:right}
.empty{color:var(--faint);padding:18px 14px;text-align:center}
.ip{font-family:var(--mono)}
.tag{display:inline-block;font-size:11px;padding:1px 7px;border-radius:99px;margin-left:8px;vertical-align:middle}
.tag.banned{background:rgba(220,38,38,.1);color:var(--bad);border:1px solid rgba(220,38,38,.3)}

/* ---- forms / controls ---- */
.inline{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
input,select{
  font:inherit;color:var(--text);background:var(--surface);
  border:1px solid var(--line);border-radius:8px;padding:8px 11px;
}
input:focus-visible,select:focus-visible,button:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
input::placeholder{color:var(--faint)}
input[type=number]{width:64px}
.btn{
  font:inherit;font-weight:600;cursor:pointer;border-radius:8px;padding:8px 15px;
  background:var(--accent);color:var(--accent-ink);border:1px solid transparent;transition:filter .12s,background .12s;
}
.btn:hover{filter:brightness(1.07)}
.btn.small{padding:5px 11px;font-size:12.5px}
.btn.ghost{background:transparent;color:var(--text);border-color:var(--line)}
.btn.ghost:hover{background:var(--surface-2);filter:none}
.btn.danger{background:transparent;color:var(--bad);border-color:rgba(220,38,38,.4)}
.btn.danger:hover{background:rgba(220,38,38,.07);filter:none}
input[type=file]{padding:6px;font-size:13px;max-width:100%}
input[type=file]::file-selector-button{
  font:inherit;font-weight:600;cursor:pointer;border:1px solid var(--line);
  background:var(--surface-2);color:var(--text);border-radius:7px;padding:6px 12px;margin-right:10px;
}
input[type=file]::file-selector-button:hover{background:var(--line-soft)}
.msg{color:var(--muted);font-size:13px}
.msg.ok{color:var(--good)}
.msg.err{color:var(--bad)}
.hint{color:var(--muted);font-size:12.5px;margin:8px 0 0;line-height:1.6}
.hint code{font-family:var(--mono);background:var(--surface-2);padding:1px 6px;border-radius:4px}
</style>
</head>
<body>
<header class="topbar">
  <div class="brand">
    <svg class="logo" width="22" height="22" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2.5l7.5 3v5.2c0 4.6-3.2 8.6-7.5 10.8-4.3-2.2-7.5-6.2-7.5-10.8V5.5l7.5-3z"/><path d="M8.8 12l2.2 2.2 4.2-4.4" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>
    <span class="name">C3 广告拦截器</span>
    <span class="host" id="host"></span>
  </div>
  <span class="live"><span class="dot" id="statusDot"></span><span id="blockstate" data-on="1">拦截已启用</span></span>
</header>

<main class="wrap">
  <div class="warn" id="credwarn" hidden>
    <svg class="warn-ico" width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3.5l9.5 16.5h-19L12 3.5z" fill="#dc2626"/><path d="M12 10.5v4" stroke="#fff" stroke-width="2" stroke-linecap="round"/><path d="M12 17.3v.1" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/></svg>
    <span>正在使用<b>默认密码</b>。<code>secrets.h</code> 中的 <code>WEB_PASS</code> / <code>OTA_PASS</code> 仍是占位值——任何能访问此页面的人都可能在公开仓库中读到它们。请设置真实值并重新烧录。</span>
  </div>

  <section class="hero" id="hero" data-state="on">
    <div class="hero-main">
      <div class="hero-label">已拦截</div>
      <div class="hero-num" id="blockedBig">—</div>
    </div>
    <div class="hero-side">
      <div class="hero-label">已放行</div>
      <div class="hero-num small" id="allowedBig">—</div>
    </div>
    <div class="hero-ctrl">
      <select id="pausedur" aria-label="暂停时长">
        <option value="30">30 秒</option>
        <option value="300" selected>5 分钟</option>
        <option value="1800">30 分钟</option>
        <option value="0">直到我手动恢复</option>
      </select>
      <button class="btn" id="pauseBtn" onclick="togglePause()">暂停</button>
    </div>
  </section>

  <div class="stats" id="sys"></div>

  <section>
    <h2>客户端</h2>
    <div class="tablewrap">
      <table id="ct">
        <thead><tr><th>客户端</th><th>MAC</th><th>已拦截</th><th>已放行</th><th></th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </section>

  <section>
    <h2>自定义拦截域名</h2>
    <div class="inline">
      <input id="dom" placeholder="ads.example.com" size="30" aria-label="要拦截的域名">
      <button class="btn" onclick="addDom()">拦截该域名</button>
    </div>
    <div class="tablewrap"><table id="cl"><tbody></tbody></table></div>
  </section>

  <section>
    <h2>拦截列表 · 上传</h2>
    <form id="upf" class="inline" style="align-items:center">
      <input type="file" id="blf" accept=".bin">
      <button class="btn">上传拦截列表</button>
      <span class="msg" id="upmsg"></span>
    </form>
    <p class="hint">用 <code>tools/build_blocklist.py</code> 构建 <code>blocklist.bin</code>，再上传到这里——无需 USB 数据线。</p>
  </section>

  <section>
    <h2>拦截列表 · 远程更新</h2>
    <div class="inline" style="align-items:center">
      <input id="uurl" placeholder="https://host/blocklist.bin" size="40" aria-label="更新地址">
      <span style="color:var(--muted)">每</span>
      <input id="uiv" type="number" min="1" value="24" aria-label="间隔小时数">
      <span style="color:var(--muted)">小时</span>
      <button class="btn" onclick="saveUpd()">保存</button>
      <button class="btn ghost" onclick="fetchNow()">立即更新</button>
    </div>
    <p class="hint">设备会按计划拉取预构建的 <code>blocklist.bin</code>（例如 GitHub Release 资源）。上次：<span id="ustat">—</span></p>
  </section>

  <section>
    <h2>固件 · OTA 更新</h2>
    <form id="fwf" class="inline" style="align-items:center">
      <input type="file" id="fwb" accept=".bin">
      <button class="btn">刷写固件</button>
      <span class="msg" id="fwmsg"></span>
    </form>
    <p class="hint">上传 <code>.pio/build/c3/firmware.bin</code>——设备会校验并在重启后进入新固件。</p>
  </section>

  <section>
    <h2>WiFi</h2>
    <button class="btn danger" onclick="if(confirm('确定要忘记已保存的 WiFi 并重启进入配置页面吗？'))forgetWifi()">忘记 WiFi</button>
  </section>
</main>

<script>
function fmt(n){return (n||0).toLocaleString()}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
// A plain <img>/<form> CSRF can't set a custom header, only same-origin fetch()
// can — so requiring this on every mutating request blocks drive-by CSRF even
// though the server can't otherwise tell a forged request from a real one over
// plain HTTP Basic Auth (browsers auto-replay cached Basic Auth cross-origin).
const CSRF_HDRS={'X-Requested-With':'c3-adblock'}
function togglePause(){fetch(blockstate.dataset.on=='1'?'/pause?s='+pausedur.value:'/resume',{headers:CSRF_HDRS}).then(load)}

async function load(){
  let s=await(await fetch('/stats.json')).json();
  host.textContent='@ '+s.ip;
  credwarn.hidden=!s.defcreds;
  let on=s.blocking!==false;
  blockstate.dataset.on=on?'1':'0';
  blockstate.textContent=on?'拦截已启用':(s.resumeIn>0?'已暂停 · '+s.resumeIn+' 秒后恢复':'已暂停');
  statusDot.className='dot'+(on?' on':' paused');
  hero.dataset.state=on?'on':'paused';
  blockedBig.textContent=fmt(s.blocked);
  allowedBig.textContent=fmt(s.allowed);
  pauseBtn.textContent=on?'暂停':'恢复';
  pausedur.style.display=on?'':'none';

  sys.innerHTML=[['拦截列表',fmt(s.domains)+' 条'],['客户端',s.clients.length+' 台'],
    ['WiFi 信号',s.rssi+' dBm'],['温度',s.temp+' °C'],
    ['可用内存',Math.round(s.heap/1024)+' KB'],['运行时间',s.uptime]]
    .map(c=>`<div class="stat"><span class="stat-v">${c[1]}</span><span class="stat-l">${c[0]}</span></div>`).join('');

  ct.tBodies[0].innerHTML=s.clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>
    `<tr><td><span class="ip">${c.ip}</span>${c.banned?'<span class="tag banned">已封禁</span>':''}</td><td class="mono">${c.mac}</td>
    <td class="num blocked">${fmt(c.blocked)}</td><td class="num allowed">${fmt(c.allowed)}</td>
    <td class="act"><button class="btn small ban ${c.banned?'danger':'ghost'}" data-ip="${c.ip}">${c.banned?'解除封禁':'封禁'}</button></td></tr>`).join('')
    || '<tr><td colspan="5" class="empty">暂无客户端——当设备开始通过此拦截器查询 DNS 后，这里会显示记录。</td></tr>';

  cl.tBodies[0].innerHTML=s.custom.map(d=>`<tr><td class="mono">${esc(d)}</td><td class="act"><button class="btn small ghost rmbtn" data-d="${esc(d)}">移除</button></td></tr>`).join('')
    || '<tr><td colspan="2" class="empty">暂无自定义域名——在上方输入域名并点击「拦截该域名」添加。</td></tr>';

  if(document.activeElement!=uurl)uurl.value=s.upurl||'';
  if(document.activeElement!=uiv)uiv.value=s.upiv||24;
  ustat.textContent=s.upstat||'—';
}

function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{dom.value='';load()})}}
ct.addEventListener('click',e=>{if(e.target.classList.contains('ban'))fetch('/ban?ip='+e.target.dataset.ip,{headers:CSRF_HDRS}).then(load)});
cl.addEventListener('click',e=>{if(e.target.classList.contains('rmbtn'))fetch('/unblock?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
function saveUpd(){fetch('/setupdate?u='+encodeURIComponent(uurl.value.trim())+'&h='+(parseInt(uiv.value)||24),{headers:CSRF_HDRS}).then(load)}
function fetchNow(){ustat.textContent='正在更新…';fetch('/fetchnow',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>{ustat.textContent=t;load()})}
function forgetWifi(){fetch('/forgetwifi',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>alert(t))}

fwf.onsubmit=async e=>{e.preventDefault();let f=fwb.files[0];if(!f)return;fwmsg.textContent='正在刷写 '+(f.size/1048576).toFixed(2)+' MB…';
  let fd=new FormData();fd.append('f',f);
  try{let r=await fetch('/update',{method:'POST',headers:CSRF_HDRS,body:fd});
    fwmsg.textContent=r.ok?'已刷写，约 15 秒后重启并重连':'失败：'+await r.text();
    fwmsg.className='msg '+(r.ok?'ok':'err');}
  catch(_){fwmsg.textContent='已刷写，约 15 秒后重启并重连';fwmsg.className='msg ok';}};

upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f)return;
  upmsg.textContent='正在上传 '+(f.size/1048576).toFixed(2)+' MB…';upmsg.className='msg';
  let fd=new FormData();fd.append('f',f);
  try{let r=await fetch('/upload',{method:'POST',headers:CSRF_HDRS,body:fd});
    upmsg.textContent=r.ok?'已更新':'失败：'+await r.text();
    upmsg.className='msg '+(r.ok?'ok':'err');}
  catch(_){upmsg.textContent='上传失败';upmsg.className='msg err';}
  blf.value='';setTimeout(load,600);};

load();setInterval(load,3000);
</script>
</body>
</html>)HTML";
