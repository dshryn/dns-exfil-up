const API_BASE = "https://dns-exfil-up-3.onrender.com";

let selectedFile = null;
let allRows = [];
let running = false;

const fileInput = document.getElementById('fileInput');
const fileName = document.getElementById('fileName');
const analyzeBtn = document.getElementById('analyzeBtn');
const dropZone = document.getElementById('dropZone');

const uploadPanel = document.getElementById('uploadPanel');
const progressPanel = document.getElementById('progressPanel');
const resultsPanel = document.getElementById('resultsPanel');
const errorPanel = document.getElementById('errorPanel');

const progressText = document.getElementById('progressText');
const statusPill = document.getElementById('statusPill');

const metricTotal = document.getElementById('metricTotal');
const metricSuspicious = document.getElementById('metricSuspicious');
const metricJob = document.getElementById('metricJob');

const resultsBody = document.getElementById('resultsBody');
const noResults = document.getElementById('noResults');
const filterInput = document.getElementById('filterInput');
const errorMsg = document.getElementById('errorMsg');

fileInput.addEventListener('change', () => {
  if (fileInput.files && fileInput.files[0]) {
    setFile(fileInput.files[0]);
  }
});

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');

  const file = e.dataTransfer.files[0];
  if (file && isPcap(file.name)) {
    setFile(file);
  } else {
    showError('Please drop a .pcap or .pcapng file.');
  }
});

document.getElementById('chooseBtn')?.addEventListener('click', (e) => {
  e.stopPropagation();
});

function isPcap(name) {
  const lower = String(name || '').toLowerCase();
  return lower.endsWith('.pcap') || lower.endsWith('.pcapng');
}

function setFile(file) {
  selectedFile = file;
  fileName.textContent = file.name;
  analyzeBtn.disabled = false;
  setStatus('READY');
}

analyzeBtn.addEventListener('click', runAnalysis);

async function runAnalysis() {
  if (!selectedFile || running) return;

  running = true;
  analyzeBtn.disabled = true;

  showOnly(progressPanel);
  setStatus('SCANNING');

  progressText.textContent = 'Uploading PCAP…';
  await sleep(250);

  const formData = new FormData();
  formData.append('file', selectedFile);

  try {
    progressText.textContent = 'Running Zeek…';

    const response = await fetch(`${API_BASE}/analyze`, {
  method: 'POST',
  body: formData,
});

if (!response.ok) {
  const text = await response.text();  
  throw new Error(text);
}

const data = await response.json();

    progressText.textContent = 'Parsing DNS records…';
    await sleep(250);

    if (!response.ok) {
      throw new Error(data.detail || `HTTP ${response.status}`);
    }

    progressText.textContent = 'Running detection…';
    await sleep(250);

    if (data.no_dns) {
      metricTotal.textContent = '0';
      metricSuspicious.textContent = '0';
      metricJob.textContent = data.job_id ?? '—';

      allRows = [];
      resultsBody.innerHTML = '';

      noResults.classList.remove('hidden');
      noResults.textContent =
        data.message || "No DNS traffic found in this PCAP";

      showOnly(resultsPanel);
      setStatus('NO DNS DATA');
      return;
    }

    allRows = Array.isArray(data.suspicious) ? data.suspicious : [];

    metricTotal.textContent = data.total_records ?? '—';
    metricSuspicious.textContent = data.suspicious_count ?? '—';
    metricJob.textContent = data.job_id ?? '—';

    renderRows(allRows);
    showOnly(resultsPanel);

    setStatus(
      (data.suspicious_count || 0) > 0 ? 'THREAT(S) FOUND' : 'CLEAN'
    );

  } catch (err) {
    showError(err.message || 'Unknown error');
  } finally {
    running = false;
    analyzeBtn.disabled = !selectedFile;
  }
}

// render
function renderRows(rows) {
  resultsBody.innerHTML = '';

  if (!rows.length) {
    noResults.classList.remove('hidden');
    noResults.textContent = "No suspicious DNS activity found";
    return;
  }

  noResults.classList.add('hidden');

  rows.forEach((row) => {
    const tr = document.createElement('tr');

    tr.innerHTML = `
      <td><span class="score ${scoreClass(row.score)}">${formatScore(row.score)}</span></td>
      <td><span class="sev ${sevClass(row.severity)}">${escapeHtml(row.severity || '-')}</span></td>
      <td class="mono">${escapeHtml(formatTs(row.timestamp))}</td>
      <td class="mono">${escapeHtml(row.src_ip || '-')}</td>
      <td class="mono">${escapeHtml(row.qtype || '-')}</td>
      <td class="query-cell mono">${escapeHtml(row.query || '-')}</td>
      <td>${escapeHtml(row.length ?? row.query_length ?? '-')}</td>
      <td>${escapeHtml(row.entropy ?? '-')}</td>
      <td class="reasons-cell">${renderReasons(row.reasons)}</td>
    `;

    resultsBody.appendChild(tr);
  });
}

function renderReasons(reasons) {
  const arr = Array.isArray(reasons) ? reasons : [];

  return `
    <div class="reason-wrap">
      ${arr.map(r => `<span class="reason">${escapeHtml(r)}</span>`).join('')}
    </div>
  `;
}

// filter
filterInput.addEventListener('input', () => {
  const q = filterInput.value.trim().toLowerCase();

  const filtered = allRows.filter((r) => {
    const reasons = Array.isArray(r.reasons) ? r.reasons.join(' ') : '';

    return [
      r.query,
      r.src_ip,
      r.qtype,
      r.severity,
      reasons,
    ].join(' ').toLowerCase().includes(q);
  });

  renderRows(filtered);
});

// reset
document.getElementById('resetBtn').addEventListener('click', resetAll);
document.getElementById('errorResetBtn').addEventListener('click', resetAll);

function resetAll() {
  selectedFile = null;
  allRows = [];
  running = false;

  fileInput.value = '';
  fileName.textContent = 'No file selected';
  analyzeBtn.disabled = true;

  filterInput.value = '';
  resultsBody.innerHTML = '';
  noResults.classList.add('hidden');

  showOnly(uploadPanel);
  setStatus('IDLE');
}

// ui helpers
function showOnly(panel) {
  [uploadPanel, progressPanel, resultsPanel, errorPanel]
    .forEach(p => p.classList.add('hidden'));

  panel.classList.remove('hidden');
}

function showError(message) {
  errorMsg.textContent = message;
  showOnly(errorPanel);
  setStatus('ERROR');
}

function setStatus(text) {
  statusPill.textContent = text;
}

function scoreClass(score) {
  const s = Number(score) || 0;
  if (s >= 85) return 'critical';
  if (s >= 70) return 'high';
  if (s >= 50) return 'medium';
  return 'low';
}

function sevClass(sev) {
  const s = String(sev || '').toUpperCase();
  if (s === 'CRITICAL') return 'critical';
  if (s === 'HIGH') return 'high';
  if (s === 'MEDIUM') return 'medium';
  return 'low';
}

function formatScore(score) {
  const n = Number(score);
  return Number.isNaN(n) ? '-' : n.toFixed(1);
}

function formatTs(ts) {
  if (ts === null || ts === undefined || ts === '') return '-';

  const n = Number(ts);
  if (Number.isNaN(n)) return String(ts);

  return new Date(n * 1000).toLocaleString();
}

function escapeHtml(value) {
  if (value === null || value === undefined) return '-';

  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}