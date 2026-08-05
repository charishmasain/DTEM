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

  // 1. Update Alert Banner (Full Width)
  const alertCard = document.getElementById('alertCard');
  const alertTitle = document.getElementById('alertTitle');
  const alertPriority = document.getElementById('alertPriority');
  const alertBody = document.getElementById('alertBody');

  const riskLevelLower = risk.risk_level.toLowerCase();
  alertCard.className = `card col-12 alert-card ${riskLevelLower}`;
  alertTitle.textContent = `DTEM Early Warning Alert — ${data.keyword.toUpperCase()}`;
  alertPriority.textContent = risk.threat_priority;

  const pClass = risk.threat_priority.split(' ')[0].toLowerCase();
  alertPriority.className = `priority-badge ${pClass}`;
  alertBody.textContent = risk.early_warning_message;

  // 2. Update KPI Summary Cards
  // Emergence Score Card
  document.getElementById('emergenceScore').textContent = emergence.emergence_score;
  const stageBadge = document.getElementById('emergenceStage');
  const stageStr = emergence.emergence_stage;
  stageBadge.textContent = stageStr;
  stageBadge.className = `badge-stage ${stageStr.toLowerCase()}`;
  document.getElementById('emergenceStageSub').textContent = stageStr;

  // Risk Score Card
  document.getElementById('riskScore').textContent = risk.risk_score;
  const riskBadge = document.getElementById('riskLevel');
  const riskStr = risk.risk_level;
  riskBadge.textContent = riskStr;
  riskBadge.className = `badge-risk ${riskStr.toLowerCase()}`;
  document.getElementById('riskLevelSub').textContent = riskStr;

  // Detection & Growth Card
  document.getElementById('detectionCount').textContent = features.detection_frequency;
  const trendBadge = document.getElementById('growthBadge');
  const trendStr = features.growth_trend;
  trendBadge.textContent = trendStr.toUpperCase();
  trendBadge.className = `badge-trend ${trendStr.toLowerCase()}`;
  document.getElementById('growthRateVal').textContent = `${features.growth_rate > 0 ? '+' : ''}${features.growth_rate}%`;

  // Exploit & Sources Card
  const exploitBadge = document.getElementById('exploitStatusBadge');
  if (features.exploit_availability) {
    exploitBadge.textContent = '🔴 Active Exploit';
    exploitBadge.className = 'badge-exploit yes';
  } else {
    exploitBadge.textContent = 'No Exploit';
    exploitBadge.className = 'badge-exploit no';
  }
  document.getElementById('sourceCount').textContent = features.source_diversity;
  document.getElementById('exploitCountVal').textContent = features.exploit_count;

  // 3. Update Sub-score Progress Bars
  const sub = emergence.sub_scores;
  updateBar('barFreq', 'valFreq', sub.detection_frequency);
  updateBar('barGrowth', 'valGrowth', sub.growth_rate);
  updateBar('barDiv', 'valDiv', sub.source_diversity);
  updateBar('barExploit', 'valExploit', sub.exploit_availability);

  // 4. Update Explainable Model Reasoning
  const reasoningList = document.getElementById('reasoningList');
  reasoningList.innerHTML = '';
  emergence.explainable_reasoning.forEach(text => {
    const div = document.createElement('div');
    div.className = 'reasoning-item';
    div.innerHTML = text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    reasoningList.appendChild(div);
  });

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

function updateBar(barId, valId, val) {
  const bar = document.getElementById(barId);
  const label = document.getElementById(valId);
  if (bar && label) {
    bar.style.width = `${val}%`;
    label.textContent = `${val.toFixed(1)} / 100`;
  }
}

/**
 * Render Chart.js Timeline Graph
 */
function renderChart(intel) {
  const ctx = document.getElementById('trendChartCtx').getContext('2d');

  // Count intel per source
  const sourceCounts = {};
  intel.forEach(item => {
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
    
    const srcTypeClass = item.source_type || 'public_api';
    const exploitBadge = item.exploit_mentioned 
      ? '<span style="color: #ef4444; font-weight: 700;">🔴 EXPLOIT</span>' 
      : '<span style="color: #6b7280;">—</span>';
    
    const dateStr = item.published_at ? new Date(item.published_at).toLocaleDateString() : 'N/A';

    tr.innerHTML = `
      <td><span class="source-tag ${srcTypeClass}">${item.source}</span></td>
      <td><span class="mono" style="font-size: 0.8rem; color: #9ca3af;">${item.source_type}</span></td>
      <td><strong style="color: #ffffff;">${item.title}</strong></td>
      <td>${dateStr}</td>
      <td>${item.severity || 'Medium'}</td>
      <td>${exploitBadge}</td>
    `;
    tbody.appendChild(tr);
  });
}

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
  const leadDays = backtest.early_warning_lead_days || 0;
  const snapshot = backtest.current_snapshot || {};

  // 1. Update Lead-Time KPI Badge
  const leadValEl = document.getElementById('leadTimeValue');
  if (leadValEl) {
    leadValEl.textContent = `+${leadDays} Days Lead`;
  }

  // 2. Update Metric Comparison Snapshot Table
  if (snapshot) {
    document.getElementById('snapDtem').textContent = snapshot.dtem !== undefined ? snapshot.dtem : 0;
    document.getElementById('snapEpss').textContent = `${snapshot.epss !== undefined ? snapshot.epss : 0}%`;
    document.getElementById('snapCvss').textContent = snapshot.cvss !== undefined ? (snapshot.cvss / 10).toFixed(1) : '8.5';
    document.getElementById('snapKev').textContent = (snapshot.cisa_kev && snapshot.cisa_kev > 0) ? 'Listed (True)' : 'Not Listed';
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
          label: 'EPSS Exploit Prob. (Lagging)',
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
          label: 'CISA KEV Status (Reactive)',
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

