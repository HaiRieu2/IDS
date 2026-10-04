async function loadAlerts() {
  try {
    const response = await fetch('/api/alerts');
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || `Flask trả về HTTP ${response.status}`);
    }
    const alerts = data.alerts || [];
    const stats = data.stats || {};
    document.getElementById('totalAlerts').textContent = stats.total ?? alerts.length;
    document.getElementById('todayAlerts').textContent = stats.today ?? 0;
    document.getElementById('highAlerts').textContent = String(stats.high ?? 0).padStart(2, '0');
    document.getElementById('donutTotal').textContent = stats.today ?? 0;
    const severity=stats.severity||{};
    const order=['critical','high','medium','low'];
    const colors=['seg','seg2','seg3','seg4'];
    let offset=0;
    order.forEach((name,index)=>{
      const count=Number(severity[name]||0);
      const pct=Number(stats.today)?count/Number(stats.today)*100:0;
      const circle=document.querySelector('.donut .'+colors[index]);
      circle.style.strokeDasharray=`${pct} ${100-pct}`;
      circle.style.strokeDashoffset=`${-offset}`;
      offset+=pct;
      document.getElementById('sev'+name[0].toUpperCase()+name.slice(1)).textContent=count;
    });
    renderRows(alerts);
  } catch (error) {
    toast(`Không thể đọc log alert: ${error.message || 'Kiểm tra Flask và logs/alerts.json.'}`);
  }
}
const severityNames = {critical:'Critical', high:'High', medium:'Medium', low:'Low'};
function fmtTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('vi-VN', {hour:'2-digit', minute:'2-digit', day:'2-digit', month:'2-digit'});
}
function safe(value) {
  const el = document.createElement('span'); el.textContent = value ?? '—'; return el.innerHTML;
}
function renderRows(alerts) {
  document.getElementById('alertCount').textContent = `${alerts.length} sự kiện`;
  const tbody = document.getElementById('alertRows');
  tbody.innerHTML = alerts.length ? alerts.slice(0, 30).map(a => `<tr data-id="${safe(a.alert_id)}"><td class="id">${safe(a.alert_id)}</td><td>${safe(fmtTime(a.timestamp))}</td><td>${safe(a.src_ip)}</td><td>${safe(a.attack_type)}</td><td><span class="sev ${safe(String(a.severity||'').toLowerCase())}">${safe(severityNames[String(a.severity||'').toLowerCase()]||a.severity)}</span></td></tr>`).join('') : '<tr><td colspan="5" class="empty-row">Chưa có alert trong file log.</td></tr>';
  tbody.querySelectorAll('tr[data-id]').forEach(row => row.addEventListener('click', () => showAlert(alerts.find(a => String(a.alert_id) === row.dataset.id))));
}
function showAlert(a) {
  if (!a) return;
  const box = document.getElementById('detailContent'); box.className = 'detail-body';
  box.innerHTML = `<div class="field wide"><label>Alert ID</label><div class="id">${safe(a.alert_id)}</div></div><div class="field"><label>Timestamp (UTC)</label><div>${safe(a.timestamp)}</div></div><div class="field"><label>Severity</label><div><span class="sev ${safe(String(a.severity||'').toLowerCase())}">${safe(severityNames[String(a.severity||'').toLowerCase()]||a.severity)}</span></div></div><div class="field"><label>Source IP</label><div>${safe(a.src_ip)}</div></div><div class="field"><label>Attack type</label><div>${safe(a.attack_type)}</div></div><div class="field"><label>Engine</label><div>${safe(a.engine)}</div></div><div class="field wide"><label>Evidence</label><div>${safe(a.evidence)}</div></div>`;
}
async function search() {
  const query = document.getElementById('searchInput').value.trim();
  if (!query) return loadAlerts();
  if (/^[a-z0-9_-]+$/i.test(query)) {
    const response = await fetch(`/api/alerts/${encodeURIComponent(query)}`);
    if (response.ok) { showAlert(await response.json()); return; }
  }
  const response = await fetch('/api/alerts'); const data = await response.json();
  const q = query.toLowerCase();
  const matches = (data.alerts||[]).filter(a => [a.alert_id,a.src_ip,a.attack_type,a.severity,a.engine,a.evidence].some(v => String(v||'').toLowerCase().includes(q)));
  renderRows(matches); if (matches.length === 1) showAlert(matches[0]);
  else if (!matches.length) { const box=document.getElementById('detailContent'); box.className='detail-empty'; box.innerHTML='<div><span>⌕</span><br>Không tìm thấy alert phù hợp.</div>'; }
}
document.getElementById('searchBtn').addEventListener('click', search);
document.getElementById('searchInput').addEventListener('keydown', e => { if (e.key === 'Enter') search(); });
let chartValues = Array(36).fill(0);
function drawChart() {
  const pts=chartValues.map((v,i)=>[40+i*(650/35),195-Math.min(4000,Math.max(0,v))/4000*170]);
  const d=pts.map((p,i)=>(i?'L':'M')+p[0].toFixed(1)+' '+p[1].toFixed(1)).join(' ');
  document.getElementById('line1').setAttribute('d',d);
  document.getElementById('areaPath').setAttribute('d',d+' L 690 195 L 40 195 Z');
  document.getElementById('line2').setAttribute('d','');
}
async function loadInterfaces() {
  try {
    const response=await fetch('/api/capture/interfaces'); const data=await response.json();
    const options=document.getElementById('interfaceOptions'); options.replaceChildren();
    (data.interfaces||[]).forEach(name=>{const option=document.createElement('option');option.value=name;options.appendChild(option);});
  } catch (_) {}
}
async function loadCaptureStatus() {
  try {
    const response=await fetch('/api/capture/status'); const state=await response.json();
    const running=Boolean(state.running);
    document.getElementById('captureStatusLabel').textContent=running?'Đang capture live':'Live capture đã dừng';
    document.getElementById('captureStatusDot').classList.toggle('stopped',!running);
    document.getElementById('captureBadge').textContent=running?'LIVE':'STOPPED';
    document.getElementById('captureBadge').classList.toggle('active',running);
    document.getElementById('startCapture').disabled=running;
    document.getElementById('stopCapture').disabled=!running;
    document.getElementById('pps').textContent=Number(state.packets_per_second||0).toLocaleString('en-US');
    chartValues.push(Number(state.packets_per_second||0)); chartValues.shift(); drawChart();
    document.getElementById('captureMessage').textContent=state.error || (running?`${state.packets||0} packet đã xử lý · ${state.sessions||0} flow trong bộ nhớ`:'Capture đang dừng.');
  } catch (error) { document.getElementById('captureMessage').textContent='Không đọc được trạng thái capture.'; }
}
document.getElementById('startCapture').addEventListener('click',async()=>{
  const message=document.getElementById('captureMessage'); message.textContent='Đang khởi động capture…';
  try {
    const response=await fetch('/api/capture/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({interface:document.getElementById('captureInterface').value,filter:document.getElementById('captureFilter').value})});
    const data=await response.json(); if(!response.ok) throw new Error(data.error||'Không khởi động được capture.');
  } catch(error) { message.textContent=error.message; }
  loadCaptureStatus();
});
document.getElementById('stopCapture').addEventListener('click',async()=>{
  document.getElementById('captureMessage').textContent='Đang dừng capture và hoàn tất flow…';
  try { const response=await fetch('/api/capture/stop',{method:'POST'}); const data=await response.json(); if(!response.ok) throw new Error(data.error||'Lỗi khi dừng capture.'); }
  catch(error) { document.getElementById('captureMessage').textContent=error.message; }
  loadCaptureStatus();
});
drawChart(); setInterval(loadCaptureStatus,1000);
const fileInput=document.getElementById('pcapFile'),drop=document.getElementById('dropArea'),analyzeButton=document.getElementById('analyzeBtn');
function updateFile(){const f=fileInput.files[0];document.getElementById('fileInfo').textContent=f?`${f.name} · ${(f.size/1048576).toFixed(2)} MB`:'Chưa chọn tệp';analyzeButton.disabled=!f;}
fileInput.addEventListener('change',updateFile);
['dragenter','dragover'].forEach(e=>drop.addEventListener(e,x=>{x.preventDefault();drop.classList.add('drag');}));
['dragleave','drop'].forEach(e=>drop.addEventListener(e,x=>{x.preventDefault();drop.classList.remove('drag');}));
drop.addEventListener('drop',e=>{const f=e.dataTransfer.files[0];if(!f)return;const transfer=new DataTransfer();transfer.items.add(f);fileInput.files=transfer.files;updateFile();});
drop.addEventListener('submit',()=>{analyzeButton.disabled=true;analyzeButton.textContent='Đang phân tích PCAP…';});function toast(text){const el=document.getElementById('toast');el.textContent=text;el.classList.add('show');setTimeout(()=>el.classList.remove('show'),3200);}
loadAlerts(); loadCaptureStatus(); loadInterfaces(); setInterval(loadAlerts,5000);
