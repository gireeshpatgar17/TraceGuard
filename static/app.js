(() => {
  const $ = (s) => document.querySelector(s);
  const form = $('#scan-form');
  const button = $('#scan-button');
  const resultPane = $('#scan-results');
  const emptyPane = $('#scan-state');
  const historyKey = 'traceguard.scans.v1';
  let currentScan = null;
  let scans = loadHistory();

  function loadHistory() { try { return JSON.parse(localStorage.getItem(historyKey) || '[]'); } catch { return []; } }
  function saveHistory() { localStorage.setItem(historyKey, JSON.stringify(scans.slice(0, 12))); }
  function esc(value) { return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  function prettyDate(iso) { if (!iso) return '—'; const date = new Date(iso); return date.toLocaleDateString(undefined, {month:'short',day:'numeric'}); }
  function toast(message) { const node = $('#toast'); node.textContent = message; node.classList.add('show'); clearTimeout(toast.timer); toast.timer = setTimeout(() => node.classList.remove('show'), 3200); }
  function severityLabel(value) { return value ? value[0].toUpperCase() + value.slice(1) : 'Info'; }

  function updateMetrics() {
    $('#history-count').textContent = scans.length;
    $('#metric-repos').textContent = scans.length ? String(new Set(scans.map(s => s.repository?.name)).size) : '—';
    $('#metric-repo-label').textContent = scans.length ? 'Unique repositories analyzed' : 'Run your first scan to begin';
    const findings = scans.reduce((n, s) => n + (s.summary?.total || 0), 0);
    const risk = scans.reduce((n, s) => n + (s.summary?.critical || 0) + (s.summary?.high || 0), 0);
    $('#metric-findings').textContent = scans.length ? String(findings) : '—';
    $('#metric-risk').textContent = scans.length ? String(risk) : '—';
    $('#metric-date').textContent = scans.length ? prettyDate(scans[0].scanned_at) : '—';
    $('#metric-date-label').textContent = scans.length ? 'Most recent completed scan' : 'No scans yet';
  }

  function findingsMarkup(scan) {
    const findings = scan.findings || [];
    const counts = scan.summary || {};
    return `<div class="repo-banner"><div><a class="repo-title" href="${esc(scan.repository?.url)}" target="_blank" rel="noopener noreferrer">${esc(scan.repository?.name || 'Repository')} ↗</a><div class="repo-sub">${esc(scan.repository?.description || 'Public GitHub repository')} &nbsp;·&nbsp; ${Number(scan.files_scanned || 0)} files &nbsp;·&nbsp; ${Number(scan.dependencies_scanned || 0)} dependencies &nbsp;·&nbsp; ${esc(prettyDate(scan.scanned_at))}</div></div><div class="result-actions"><button class="small-button" id="export-json">↓ JSON</button><button class="small-button" id="export-csv">↓ CSV</button></div></div><div class="result-summary"><div class="sum-item"><span>TOTAL FINDINGS</span><strong>${Number(counts.total || 0)}</strong></div><div class="sum-item critical"><span>CRITICAL</span><strong>${Number(counts.critical || 0)}</strong></div><div class="sum-item high"><span>HIGH</span><strong>${Number(counts.high || 0)}</strong></div><div class="sum-item medium"><span>MEDIUM</span><strong>${Number(counts.medium || 0)}</strong></div><div class="sum-item low"><span>LOW</span><strong>${Number(counts.low || 0)}</strong></div></div><div class="findings-toolbar"><strong>Findings <span style="color:#77869b;font-weight:400">(${findings.length})</span></strong><select class="filter-select" id="category-filter" aria-label="Filter by category"><option value="all">All categories</option><option>Dependency</option><option>Secret</option><option>Code</option></select><select class="filter-select" id="severity-filter" aria-label="Filter by severity"><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div><div class="finding-list" id="finding-list">${findings.length ? findings.map((f, i) => `<article class="finding-card" data-category="${esc(f.category)}" data-severity="${esc(f.severity)}"><div class="finding-main" role="button" tabindex="0" aria-expanded="false"><div class="finding-bar sev-${esc(f.severity)}"></div><div><div class="finding-name">${esc(f.title)}</div><div class="finding-location">${esc(f.file)}${f.line ? `:${Number(f.line)}` : ''}${f.target ? ` &nbsp;·&nbsp; ${esc(f.target)}` : ''}</div></div><span class="badge ${esc(f.severity)}">${esc(severityLabel(f.severity))}</span><span class="chevron">⌄</span></div><div class="finding-detail"><p><strong>Evidence</strong><br/>${esc(f.evidence)}</p>${f.fix ? `<p><strong>Suggested action</strong><br/>${esc(f.fix)}</p>` : ''}<div class="finding-help"><strong>TraceGuard explanation</strong><br/>${esc(f.explanation || '')}</div>${f.url ? `<p style="margin-top:8px"><a href="${esc(f.url)}" target="_blank" rel="noopener noreferrer">View upstream advisory ↗</a></p>` : ''}</div></article>`).join('') : '<div class="no-findings">No findings detected in the scanned files. Keep your dependencies and secrets under review.</div>'}</div>`;
  }

  function showScan(scan) {
    currentScan = scan;
    emptyPane.classList.add('hidden');
    resultPane.classList.remove('hidden');
    resultPane.innerHTML = findingsMarkup(scan);
    bindResultActions();
    resultPane.scrollIntoView({behavior:'smooth', block:'nearest'});
  }

  function bindResultActions() {
    $('#export-json').addEventListener('click', () => download(`${safeFile(currentScan.repository?.name)}-traceguard.json`, JSON.stringify(currentScan, null, 2), 'application/json'));
    $('#export-csv').addEventListener('click', () => {
      const rows = [['Severity','Category','Finding','File','Line','Target','Evidence','Suggested action','Source']];
      (currentScan.findings || []).forEach(f => rows.push([f.severity,f.category,f.title,f.file,f.line || '',f.target || '',f.evidence,f.fix || '',f.source || '']));
      const csv = rows.map(row => row.map(v => `"${String(v ?? '').replaceAll('"','""')}"`).join(',')).join('\r\n');
      download(`${safeFile(currentScan.repository?.name)}-traceguard.csv`, csv, 'text/csv');
    });
    const list = $('#finding-list');
    list.querySelectorAll('.finding-main').forEach(row => {
      const toggle = () => { const card = row.closest('.finding-card'); card.classList.toggle('open'); row.setAttribute('aria-expanded', card.classList.contains('open')); };
      row.addEventListener('click', toggle);
      row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
    });
    const filter = () => list.querySelectorAll('.finding-card').forEach(card => {
      const category = $('#category-filter').value;
      const severity = $('#severity-filter').value;
      card.classList.toggle('hidden', (category !== 'all' && card.dataset.category !== category) || (severity !== 'all' && card.dataset.severity !== severity));
    });
    $('#category-filter').addEventListener('change', filter);
    $('#severity-filter').addEventListener('change', filter);
  }

  function safeFile(value) { return String(value || 'repository').replace(/[^a-z0-9_-]/gi, '-').toLowerCase(); }
  function download(name, text, type) { const blob = new Blob([text], {type}); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    const url = $('#repo-url').value.trim();
    button.disabled = true;
    button.innerHTML = '<span class="spinner"></span><span>Scanning…</span>';
    try {
      const response = await fetch('/api/scan', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({repository_url:url})});
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'The scan could not be completed.');
      scans = [data, ...scans.filter(s => s.repository?.name !== data.repository?.name)].slice(0, 12);
      saveHistory(); updateMetrics(); showScan(data); toast(`Analysis complete · ${data.summary.total} finding${data.summary.total === 1 ? '' : 's'}`);
    } catch (error) { toast(error.message || 'Could not connect to TraceGuard. Is the server running?'); }
    finally { button.disabled = false; button.innerHTML = '<span>Start scan</span><span class="button-arrow">↗</span>'; }
  });

  $('#view-all').addEventListener('click', () => {
    if (!scans.length) { toast('Your completed scans will appear here.'); return; }
    $('#crumb-current').textContent = 'Scan history';
    emptyPane.classList.add('hidden'); resultPane.classList.remove('hidden');
    resultPane.innerHTML = `<div class="repo-banner"><div><div class="repo-title">Scan history</div><div class="repo-sub">Your recent analyses are saved in this browser.</div></div><button class="small-button" id="back-overview">← Latest report</button></div>${scans.map((scan, i) => `<div class="history-row"><div><a class="repo-title" href="${esc(scan.repository?.url)}" target="_blank" rel="noopener noreferrer">${esc(scan.repository?.name)} ↗</a><div class="repo-sub">${esc(prettyDate(scan.scanned_at))} · ${Number(scan.files_scanned || 0)} files · ${Number(scan.summary?.total || 0)} findings</div></div><button class="small-button" data-history-index="${i}">Open report →</button></div>`).join('')}`;
    $('#back-overview').addEventListener('click', () => { $('#crumb-current').textContent = 'Overview'; showScan(currentScan || scans[0]); });
    resultPane.querySelectorAll('[data-history-index]').forEach(el => el.addEventListener('click', () => { const scan = scans[Number(el.dataset.historyIndex)]; $('#crumb-current').textContent = 'Overview'; showScan(scan); }));
  });
  document.querySelectorAll('.nav-item').forEach(el => el.addEventListener('click', () => { if (el.dataset.view === 'scans') $('#view-all').click(); else { $('#crumb-current').textContent = 'Overview'; if (currentScan) showScan(currentScan); else { resultPane.classList.add('hidden'); emptyPane.classList.remove('hidden'); } } }));
  $('#close-dialog').addEventListener('click', () => $('#finding-dialog').close());
  updateMetrics();
  if (scans.length) showScan(scans[0]);
})();
