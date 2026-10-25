/**
 * DTEM — Dynamic Threat Emergence Model Dashboard JavaScript (Redesigned)
 */

let trendChart = null;
let baselineChart = null;

document.addEventListener('DOMContentLoaded', () => {
  // Bind form search submit
  const searchForm = document.getElementById('searchForm');
  if (searchForm) {
    searchForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const kw = document.getElementById('searchInput').value.trim();
      if (kw) {
        analyzeKeyword(kw);
      }
    });
  }

  // Bind quick suggestions chips
  document.querySelectorAll('.quick-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const kw = chip.getAttribute('data-kw');
      if (kw) {
        document.getElementById('searchInput').value = kw;
        analyzeKeyword(kw);
      }
    });
  });

  // Initial load with default input value
  const initialKw = document.getElementById('searchInput').value.trim();
  if (initialKw) {
    analyzeKeyword(initialKw);
  }
  bindMonitoringControls();
  loadMonitoringDashboard();
  loadMonitoringSettings();
});

/**
 * Fetch complete DTEM analysis via FastAPI endpoint
 */
async function analyzeKeyword(keyword) {
  showLoading(true);

  try {
    const response = await fetch(`/api/analyze?keyword=${encodeURIComponent(keyword)}`);
    if (!response.ok) {
      throw new Error(`Server returned HTTP ${response.status}`);
    }

    const data = await response.json();
    renderDashboard(data);
  } catch (err) {
    console.error('Analysis failed:', err);
    alert(`Error analyzing threat '${keyword}': ${err.message}`);
  } finally {
    showLoading(false);
  }
}

/**
 * Render all dashboard UI components with API data
 */
function renderDashboard(data) {
  const emergence = data.emergence;
  const risk = data.risk;
  const features = data.features;
  const intel = data.collected_intel;
  const hasScore = emergence.score_status !== 'insufficient_data';
  const hasGrowth = hasScore && features.growth_rate != null;

  // 1. Update Alert Banner (Full Width)
  const alertCard = document.getElementById('alertCard');
  const alertTitle = document.getElementById('alertTitle');
  const alertPriority = document.getElementById('alertPriority');
  const alertBody = document.getElementById('alertBody');

  const riskLevelLower = String(risk.risk_level || 'unavailable').toLowerCase();
  alertCard.className = `card col-12 alert-card ${riskLevelLower}`;
  alertTitle.textContent = data.generated_alerts?.length
    ? `Persistent DTEM Alert — ${data.keyword.toUpperCase()}`
    : `DTEM Analysis Advisory — ${data.keyword.toUpperCase()}`;
  alertPriority.textContent = risk.threat_priority;

  const pClass = risk.threat_priority.split(' ')[0].toLowerCase();
  alertPriority.className = `priority-badge ${pClass}`;
  alertBody.textContent = risk.early_warning_message;

  // 2. Update KPI Summary Cards
  // Emergence Score Card
  document.getElementById('emergenceScore').textContent = hasScore ? emergence.emergence_score : 'N/A';
  const stageBadge = document.getElementById('emergenceStage');
  const stageStr = hasScore ? emergence.emergence_stage : 'Insufficient data';
  stageBadge.textContent = stageStr;
  stageBadge.className = `badge-stage ${hasScore ? stageStr.toLowerCase() : 'unavailable'}`;
  document.getElementById('emergenceStageSub').textContent = stageStr;

  // Risk Score Card
  document.getElementById('riskScore').textContent = risk.risk_score == null ? 'N/A' : risk.risk_score;
  const riskBadge = document.getElementById('riskLevel');
  const riskStr = risk.risk_level;
  riskBadge.textContent = riskStr;
  riskBadge.className = `badge-risk ${String(riskStr || 'unavailable').toLowerCase()}`;
  document.getElementById('riskLevelSub').textContent = riskStr;

  // Detection & Growth Card
  document.getElementById('detectionCount').textContent = features.detection_frequency;
  const trendBadge = document.getElementById('growthBadge');
  const trendStr = features.growth_trend;
  trendBadge.textContent = hasGrowth ? trendStr.toUpperCase() : 'NO DATA';
  trendBadge.className = `badge-trend ${hasGrowth ? trendStr.toLowerCase() : 'unavailable'}`;
  document.getElementById('growthRateVal').textContent = hasGrowth ? `${features.growth_rate > 0 ? '+' : ''}${features.growth_rate}%` : 'N/A';

  // Exploit & Sources Card
  const exploitBadge = document.getElementById('exploitStatusBadge');
  if (!hasScore) {
    exploitBadge.textContent = 'No eligible data';
    exploitBadge.className = 'badge-exploit no';
  } else if (features.exploit_availability) {
    exploitBadge.textContent = `Evidence: ${(features.exploit_evidence_level || 'unclassified').replaceAll('_', ' ')}`;
    exploitBadge.className = 'badge-exploit yes';
  } else {
    exploitBadge.textContent = 'No Exploit';
    exploitBadge.className = 'badge-exploit no';
  }
  document.getElementById('sourceCount').textContent = features.source_diversity;
  document.getElementById('exploitCountVal').textContent = features.exploit_count;

  // 3. Update Sub-score Progress Bars
  const sub = emergence.sub_scores;
  updateBar('barFreq', 'valFreq', sub.detection_frequency, hasScore);
  updateBar('barGrowth', 'valGrowth', sub.growth_rate, hasGrowth);
  updateBar('barDiv', 'valDiv', sub.source_diversity, hasScore);
  updateBar('barExploit', 'valExploit', sub.exploit_availability, hasScore);

  // 4. Update Explainable Model Reasoning
  const reasoningList = document.getElementById('reasoningList');
  reasoningList.innerHTML = '';
  emergence.explainable_reasoning.forEach(text => {
    const div = document.createElement('div');
    div.className = 'reasoning-item';
    div.textContent = text.replace(/\*\*/g, '');
    reasoningList.appendChild(div);
  });
  const caveat=document.createElement('div');caveat.className='reasoning-item';
  caveat.textContent=features.evidence_quality_caveat||'Evidence quality depends on source attribution and record quality.';
  reasoningList.appendChild(caveat);

  // 5. Update Recommendations List
  const recList = document.getElementById('recommendationsList');
  recList.innerHTML = '';
  risk.recommendations.forEach(rec => {
    const li = document.createElement('li');
    li.textContent = rec;
    recList.appendChild(li);
  });

  // 6. Render Source Distribution Chart
  renderChart(intel);

  // 7. Render Retrospective Baseline Comparison Panel
  if (data.timeline_backtest) {
    renderBaselineComparison(data.timeline_backtest);
  }

  // 8. Render Intel Table
  renderTable(intel);

  showResults(true);
}

function updateBar(barId, valId, val, available = true) {
  const bar = document.getElementById(barId);
  const label = document.getElementById(valId);
  if (bar && label) {
    bar.style.width = `${val}%`;
    label.textContent = available ? `${val.toFixed(1)} / 100` : 'N/A';
  }
}

/**
 * Render Chart.js Timeline Graph
 */
function renderChart(intel) {
  const ctx = document.getElementById('trendChartCtx').getContext('2d');

  // Count intel per source
  const sourceCounts = {};
  intel.filter(item => !item.demonstration_data).forEach(item => {
    const src = item.source || 'Unknown';
    sourceCounts[src] = (sourceCounts[src] || 0) + 1;
  });

  const labels = Object.keys(sourceCounts);
  const counts = Object.values(sourceCounts);

  if (trendChart) {
    trendChart.destroy();
  }

  trendChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Collected Intelligence Records',
        data: counts,
        backgroundColor: [
          'rgba(0, 242, 254, 0.6)',
          'rgba(59, 130, 246, 0.6)',
          'rgba(168, 85, 247, 0.6)',
          'rgba(245, 158, 11, 0.6)',
          'rgba(239, 68, 68, 0.6)'
        ],
        borderColor: [
          '#00f2fe',
          '#3b82f6',
          '#a855f7',
          '#f59e0b',
          '#ef4444'
        ],
        borderWidth: 1.5,
        borderRadius: 6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
      },
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#9ca3af', font: { family: 'Inter', size: 12 } }
        },
        y: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#9ca3af', precision: 0, font: { family: 'Inter', size: 12 } },
          beginAtZero: true
        }
      }
    }
  });
}

/**
 * Render Intel Feed Table
 */
function renderTable(intel) {
  const tbody = document.getElementById('intelTableBody');
  tbody.innerHTML = '';

  intel.forEach(item => {
    const tr = document.createElement('tr');
    
    const values = [item.source || 'Unknown', item.demonstration_data ? 'SIMULATED DEMONSTRATION' : item.source_type || 'Unknown',
      `${item.demonstration_data ? '[DEMO DATA] ' : ''}${item.title || ''}`,
      item.published_at ? new Date(item.published_at).toLocaleString() : 'N/A', item.severity || 'Unavailable',
      item.exploit_evidence_level || (item.exploit_mentioned ? 'Unclassified mention' : 'No evidence')];
    values.forEach((value, index) => {
      const td = document.createElement('td');
      td.textContent = value;
      if (index === 2 && item.url) {
        td.textContent = '';
        const a = document.createElement('a');
        a.href = item.url;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.textContent = value;
        td.appendChild(a);
      }
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

function bindMonitoringControls() {
  document.getElementById('refreshOverview')?.addEventListener('click', loadMonitoringDashboard);
  ['filterCve','filterRisk','filterCategory','filterSource','filterDays','threatSort'].forEach(id => {
    document.getElementById(id)?.addEventListener('change', loadMonitoringDashboard);
  });
  document.getElementById('filterCve')?.addEventListener('input', debounce(loadMonitoringDashboard, 300));
  document.getElementById('monitorStart')?.addEventListener('click', () => monitoringAction('start'));
  document.getElementById('monitorStop')?.addEventListener('click', () => monitoringAction('stop'));
  document.getElementById('monitorRun')?.addEventListener('click', async () => {
    await requestJson('/api/monitoring/run', {method:'POST'});
    await loadMonitoringDashboard();
  });
  document.getElementById('saveSettings')?.addEventListener('click', saveMonitoringSettings);
  document.getElementById('watchlistForm')?.addEventListener('submit', async event => {
    event.preventDefault();
    const keyword = document.getElementById('watchKeyword').value.trim();
    const category = document.getElementById('watchCategory').value;
    await requestJson('/api/watchlist', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({keyword,category})});
    event.target.reset();
    await loadMonitoringDashboard();
  });
  document.getElementById('watchlistRows')?.addEventListener('click', async event => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    const keyword = button.dataset.keyword;
    if (button.dataset.action === 'remove') await requestJson(`/api/watchlist/${encodeURIComponent(keyword)}`, {method:'DELETE'});
    if (button.dataset.action === 'pause' || button.dataset.action === 'resume') {
      await requestJson(`/api/watchlist/${encodeURIComponent(keyword)}`, {method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:button.dataset.action==='resume'})});
    }
    if (button.dataset.action === 'analyze') analyzeKeyword(keyword);
    await loadMonitoringDashboard();
  });
  ['alertHistoryPanel'].forEach(id => document.getElementById(id)?.addEventListener('click', async event => {
    const button = event.target.closest('button[data-alert-status]');
    if (!button) return;
    await requestJson(`/api/alerts/${button.dataset.alertId}`, {method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:button.dataset.alertStatus})});
    await loadMonitoringDashboard();
  }));
}

function debounce(fn, wait) { let timer; return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), wait); }; }

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
  return data;
}

async function monitoringAction(action) {
  await requestJson(`/api/monitoring/${action}`, {method:'POST'});
  await loadMonitoringDashboard();
}

async function loadMonitoringSettings() {
  try {
    const s = await requestJson('/api/settings');
    document.getElementById('alertThresholdInput').value = s.alert_threshold;
    document.getElementById('increaseThresholdInput').value = s.significant_score_increase;
    document.getElementById('minimumRiskInput').value = s.minimum_alert_risk;
    document.getElementById('intervalInput').value = s.interval_seconds;
    [...document.getElementById('sourceInput').options].forEach(option => { option.selected = s.sources.includes(option.value); });
  } catch (error) { console.error('Could not load monitoring settings', error); }
}

async function saveMonitoringSettings() {
  await requestJson('/api/settings', {method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({
    alert_threshold:Number(document.getElementById('alertThresholdInput').value),
    significant_score_increase:Number(document.getElementById('increaseThresholdInput').value),
    minimum_alert_risk:document.getElementById('minimumRiskInput').value,
    interval_seconds:Number(document.getElementById('intervalInput').value),
    sources:[...document.getElementById('sourceInput').selectedOptions].map(option=>option.value)
  })});
  document.getElementById('monitoringStatusText').textContent = 'Settings saved';
}

async function loadMonitoringDashboard() {
  const params = new URLSearchParams();
  const mapping = {cve:'filterCve',risk_level:'filterRisk',category:'filterCategory',source:'filterSource',days:'filterDays',sort:'threatSort'};
  Object.entries(mapping).forEach(([param,id]) => { const value=document.getElementById(id)?.value; if(value) params.set(param,value); });
  try {
    const data = await requestJson(`/api/dashboard?${params}`);
    renderMonitoringDashboard(data);
  } catch (error) {
    document.getElementById('monitoringStatusText').textContent = `Dashboard data unavailable: ${error.message}`;
  }
}

function renderMonitoringDashboard(data) {
  const overview=data.overview||{};
  // Read the collection-run values before rendering the collector-health panel.
  // Referencing `run` earlier triggers a temporal-dead-zone ReferenceError and
  // aborts dashboard rendering, making the controls appear unresponsive.
  const run=data.last_collection;
  const success=data.last_successful_collection;
  document.getElementById('trackedCount').textContent=overview.tracked??0;
  document.getElementById('analyzedCount').textContent=overview.analyzed??0;
  document.getElementById('meanEmergence').textContent=overview.mean_emergence==null?'—':overview.mean_emergence;
  document.getElementById('openAlertsCount').textContent=(data.alerts||[]).filter(a=>a.status==='open').length;
  const sourceSelect=document.getElementById('filterSource');
  const chosen=sourceSelect.value;
  const sources=[...new Set((data.recent_activity||[]).map(r=>r.source).filter(Boolean))].sort();
  sourceSelect.replaceChildren(new Option('All sources',''),...sources.map(s=>new Option(s,s)));
  if(sources.includes(chosen)) sourceSelect.value=chosen;
  const rows=document.getElementById('watchlistRows'); rows.replaceChildren();
  if(!(data.threats||[]).length) addEmpty(rows,8,'No tracked threats match this filter.');
  (data.threats||[]).forEach(item=>{
    const tr=document.createElement('tr'); const latest=item.latest;
    [item.keyword,item.category,latest?`${latest.emergence_score} / 100`:'No stored analysis',
      latest?.risk_score==null?'Unavailable':`${latest.risk_score} / 100`,latest?.risk_level||'—',
      item.score_delta==null?'—':`${item.score_delta>0?'+':''}${item.score_delta}`,latest?.analyzed_at?new Date(latest.analyzed_at).toLocaleString():'—'].forEach(text=>{const td=document.createElement('td');td.textContent=text;tr.appendChild(td);});
    const action=document.createElement('td');
    action.append(makeAction('Analyze','analyze',item.keyword),makeAction(item.enabled?'Pause':'Resume',item.enabled?'pause':'resume',item.keyword),makeAction('Remove','remove',item.keyword));
    const detail=document.createElement('a'); detail.href=`/threat/${encodeURIComponent(item.keyword)}`; detail.textContent=' History'; action.appendChild(detail);
    const report=document.createElement('a'); report.href=`/report/${encodeURIComponent(item.keyword)}`; report.textContent=' Report'; action.appendChild(report); tr.appendChild(action); rows.appendChild(tr);
  });
  renderOperationsList('alertHistoryPanel',data.alerts||[],(a)=>{
    const box=document.createElement('div'); box.className='operations-row';
    box.textContent=`${a.keyword} — ${a.alert_type.replace('_',' ')}: ${a.previous_score==null?'—':a.previous_score} → ${a.new_score} (${a.risk_level||'unknown'}), ${new Date(a.created_at).toLocaleString()} · ${a.status}`;
    if(a.status==='open') box.appendChild(makeAlertAction('Acknowledge',a.id,'acknowledged'));
    if(a.status!=='resolved') box.appendChild(makeAlertAction('Resolve',a.id,'resolved'));
    return box;
  });
  renderOperationsList('recentActivityPanel',data.recent_activity||[],r=>{
    const box=document.createElement('div'); box.className='operations-row';
    box.textContent=`${r.source} · ${r.keyword}: ${r.title} · collected ${r.collected_at?new Date(r.collected_at+'Z').toLocaleString():'time unavailable'}`; return box;
  });
  const health=document.getElementById('collectorHealthPanel');health.replaceChildren();
  if(!run) { const empty=document.createElement('div');empty.className='empty-state';empty.textContent='No monitoring run recorded.';health.appendChild(empty); }
  else {
    let details={}; try { details=JSON.parse(run.error||'{}'); } catch (_) { details={errors:[run.error]}; }
    (details.sources||[]).forEach(s=>{const p=document.createElement('div');p.className='operations-row';p.textContent=`${s.keyword||''} ${s.source}: ${s.status} (${s.record_count||0} records)${s.error?` — ${s.error}`:''}`;health.appendChild(p);});
    (details.errors||[]).forEach(e=>{const p=document.createElement('div');p.className='operations-row';p.textContent=e;health.appendChild(p);});
    if(!health.childNodes.length){const p=document.createElement('div');p.className='empty-state';p.textContent='No source errors reported.';health.appendChild(p);}
  }
  const dist=document.getElementById('riskDistributionPanel'); dist.replaceChildren();
  const entries=Object.entries(overview.risk_distribution||{});
  if(!entries.length) addEmpty(dist,1,'No stored analyses yet.');
  entries.forEach(([level,count])=>{const p=document.createElement('div');p.className='operations-row';p.textContent=`${level}: ${count}`;dist.appendChild(p);});
  renderOperationsList('rapidThreatPanel',overview.rapidly_increasing||[],t=>{const p=document.createElement('div');p.className='operations-row';p.textContent=`${t.keyword}: +${t.score_delta} score since prior stored analysis`;return p;});
  renderOperationsList('exploitSummaryPanel',overview.exploit_evidence||[],item=>{
    const p=document.createElement('div');p.className='operations-row';
    p.textContent=`${item.keyword}: ${item.level.replaceAll('_',' ')} · ${item.items.length} heuristic evidence item(s)`;
    return p;
  });
  const mon=data.monitoring||{};
  document.getElementById('monitoringStatusText').textContent=mon.running?'Periodic public-feed monitoring is running':'Monitoring is stopped; use Start or Run once';
  document.getElementById('lastRunLabel').textContent=`Latest run: ${run?`${run.status} at ${new Date(run.finished_at).toLocaleString()} (${run.inserted_count} new records)`:'none'} · Last successful: ${success?new Date(success.finished_at).toLocaleString():'none'}`;
}

function makeAction(label,action,keyword){const b=document.createElement('button');b.className='watch-action'+(action==='remove'?' remove':'');b.textContent=label;b.dataset.action=action;b.dataset.keyword=keyword;return b;}
function makeAlertAction(label,id,status){const b=document.createElement('button');b.textContent=label;b.dataset.alertId=id;b.dataset.alertStatus=status;return b;}
function addEmpty(parent,colspan,text){const tr=document.createElement('tr');const td=document.createElement('td');td.colSpan=colspan;td.className='empty-state';td.textContent=text;tr.appendChild(td);parent.appendChild(tr);}
function renderOperationsList(id,items,render){const parent=document.getElementById(id);parent.replaceChildren();if(!items.length){const empty=document.createElement('div');empty.className='empty-state';empty.textContent='No stored records yet.';parent.appendChild(empty);return;}items.forEach(item=>parent.appendChild(render(item)));}

function showLoading(state) {
  document.getElementById('loadingOverlay').style.display = state ? 'block' : 'none';
  if (state) {
    document.getElementById('resultsContainer').style.display = 'none';
  }
}

function showResults(state) {
  document.getElementById('resultsContainer').style.display = state ? 'grid' : 'none';
}

/**
 * Render Retrospective Baseline Comparison Chart and Snapshot Table
 */
function renderBaselineComparison(backtest) {
  const timeline = backtest.timeline || [];
  const leadDays = backtest.early_warning_lead_days;
  const snapshot = backtest.current_snapshot || {};

  // 1. Update Lead-Time KPI Badge
  const leadValEl = document.getElementById('leadTimeValue');
  if (leadValEl) {
    leadValEl.textContent = Number.isFinite(leadDays) ? `${leadDays > 0 ? '+' : ''}${leadDays} Days` : 'Not estimated';
  }

  // 2. Update Metric Comparison Snapshot Table
  if (snapshot) {
    document.getElementById('snapDtem').textContent = snapshot.dtem == null ? 'Unavailable' : snapshot.dtem;
    document.getElementById('snapEpss').textContent = snapshot.epss != null ? `${snapshot.epss}%` : 'Unavailable';
    document.getElementById('snapCvss').textContent = snapshot.cvss != null ? (snapshot.cvss / 10).toFixed(1) : 'Unavailable';
    document.getElementById('snapKev').textContent = snapshot.cisa_kev == null ? 'Unavailable' : snapshot.cisa_kev > 0 ? 'Listed' : 'Not listed';
  }

  // 3. Render Chart.js Multi-Line Timeline Chart
  const ctx = document.getElementById('baselineChartCtx');
  if (!ctx) return;

  const labels = timeline.map(t => `T${t.day >= 0 ? '+' : ''}${t.day}d`);
  const dtemData = timeline.map(t => t.dtem);
  const epssData = timeline.map(t => t.epss);
  const cvssData = timeline.map(t => t.cvss);
  const kevData = timeline.map(t => t.cisa_kev);

  if (baselineChart) {
    baselineChart.destroy();
  }

  baselineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'DTEM Emergence Score (Dynamic)',
          data: dtemData,
          borderColor: '#00f2fe',
          backgroundColor: 'rgba(0, 242, 254, 0.1)',
          borderWidth: 3,
          pointRadius: 4,
          pointBackgroundColor: '#00f2fe',
          tension: 0.3,
          fill: true
        },
        {
          label: 'EPSS (unavailable without historical observations)',
          data: epssData,
          borderColor: '#a855f7',
          backgroundColor: 'transparent',
          borderWidth: 2.5,
          pointRadius: 3,
          pointBackgroundColor: '#a855f7',
          tension: 0.3
        },
        {
          label: 'CVSS Base Score (Static)',
          data: cvssData,
          borderColor: '#6b7280',
          borderDash: [5, 5],
          backgroundColor: 'transparent',
          borderWidth: 2,
          pointRadius: 0,
          tension: 0
        },
        {
          label: 'CISA KEV (unavailable without dated event records)',
          data: kevData,
          borderColor: '#ef4444',
          backgroundColor: 'transparent',
          borderWidth: 2,
          stepped: true,
          pointRadius: 0
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: 'index',
        intersect: false
      },
      plugins: {
        legend: {
          display: true,
          position: 'top',
          labels: {
            color: '#9ca3af',
            font: { family: 'Inter', size: 11 },
            boxWidth: 12,
            padding: 15
          }
        },
        tooltip: {
          backgroundColor: 'rgba(17, 24, 39, 0.9)',
          titleColor: '#ffffff',
          bodyColor: '#d1d5db',
          borderColor: 'rgba(255, 255, 255, 0.1)',
          borderWidth: 1,
          padding: 10,
          displayColors: true
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#9ca3af', font: { family: 'Inter', size: 11 } },
          title: { display: true, text: 'Timeline (Days Relative to Outbreak)', color: '#6b7280', font: { size: 11 } }
        },
        y: {
          min: 0,
          max: 105,
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#9ca3af', font: { family: 'Inter', size: 11 } },
          title: { display: true, text: 'Normalized Value (0 - 100)', color: '#6b7280', font: { size: 11 } }
        }
      }
    }
  });
}

