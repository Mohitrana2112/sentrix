/**
 * SENTRIX Chart.js Visualizations
 * Circular Intelligence Radar, Radial Risk Doughnut, Threat Classification, Timeline
 */

let intelligenceRadarChart = null;
let riskDistributionChart = null;
let activityTimelineChart = null;
let threatClassificationChart = null;

function getChartColors(theme = 'dark') {
  if (theme === 'light') {
    return {
      textColor: '#475569',
      gridColor: 'rgba(15, 23, 42, 0.08)',
      radarBg: 'rgba(2, 132, 199, 0.2)',
      radarBorder: '#0284C7',
      cyan: '#0284C7',
      blue: '#2563EB',
      amber: '#D97706',
      red: '#DC2626',
      green: '#059669',
    };
  }
  return {
    textColor: '#94A3B8',
    gridColor: 'rgba(255, 255, 255, 0.08)',
    radarBg: 'rgba(0, 213, 255, 0.25)',
    radarBorder: '#00D5FF',
    cyan: '#00D5FF',
    blue: '#2878FF',
    amber: '#FFB547',
    red: '#FF5263',
    green: '#21D4A5',
  };
}

function initDashboardCharts() {
  const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
  const colors = getChartColors(currentTheme);

  // 1. Circular Intelligence Radar Chart
  const radarCtx = document.getElementById('intelligenceRadarChart');
  if (radarCtx && !intelligenceRadarChart) {
    intelligenceRadarChart = new Chart(radarCtx, {
      type: 'radar',
      data: {
        labels: [
          'Phishing Patterns',
          'Domain Typosquatting',
          'Punycode / Obfuscation',
          'Insecure Transport',
          'DNS / DMARC Anomalies',
          'Header Deficiencies'
        ],
        datasets: [{
          label: 'Observed Exposure Vector',
          data: [75, 45, 60, 85, 40, 65],
          backgroundColor: colors.radarBg,
          borderColor: colors.radarBorder,
          pointBackgroundColor: colors.cyan,
          pointBorderColor: '#fff',
          pointHoverBackgroundColor: '#fff',
          pointHoverBorderColor: colors.cyan,
          borderWidth: 2,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          r: {
            angleLines: { color: colors.gridColor },
            grid: { color: colors.gridColor },
            pointLabels: {
              color: colors.textColor,
              font: { size: 10, weight: '600' }
            },
            ticks: { display: false, max: 100, min: 0 }
          }
        }
      }
    });
  }

  // 2. Radial Risk Distribution Doughnut Chart
  const riskCtx = document.getElementById('riskDistributionChart');
  if (riskCtx && !riskDistributionChart) {
    riskDistributionChart = new Chart(riskCtx, {
      type: 'doughnut',
      data: {
        labels: ['Low Risk', 'Medium Risk', 'High Risk', 'Critical'],
        datasets: [{
          data: [42, 28, 18, 12],
          backgroundColor: [
            colors.green,
            colors.amber,
            '#FF7A00',
            colors.red
          ],
          borderWidth: 0,
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '72%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: colors.textColor,
              boxWidth: 10,
              padding: 12,
              font: { size: 11, weight: '600' }
            }
          }
        }
      }
    });
  }

  // 3. Investigation Activity Timeline Chart
  const timelineCtx = document.getElementById('activityTimelineChart');
  if (timelineCtx && !activityTimelineChart) {
    timelineCtx.getContext('2d');
    activityTimelineChart = new Chart(timelineCtx, {
      type: 'line',
      data: {
        labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', 'Now'],
        datasets: [{
          label: 'URLs Scanned',
          data: [14, 22, 45, 68, 54, 82, 95],
          borderColor: colors.cyan,
          backgroundColor: 'rgba(0, 213, 255, 0.08)',
          fill: true,
          tension: 0.35,
          borderWidth: 2.5,
          pointRadius: 4,
          pointBackgroundColor: colors.cyan
        }, {
          label: 'Threat Anomalies',
          data: [2, 5, 12, 18, 14, 26, 31],
          borderColor: colors.red,
          backgroundColor: 'transparent',
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: colors.red
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: {
              color: colors.textColor,
              font: { size: 11, weight: '600' }
            }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: colors.textColor }
          },
          y: {
            grid: { color: colors.gridColor },
            ticks: { color: colors.textColor }
          }
        }
      }
    });
  }

  // 4. Threat Classification Chart
  const threatClassCtx = document.getElementById('threatClassificationChart');
  if (threatClassCtx && !threatClassificationChart) {
    threatClassificationChart = new Chart(threatClassCtx, {
      type: 'bar',
      data: {
        labels: ['Brand Spoofing', 'Raw IP Hosting', 'Punycode Obfuscation', 'Insecure HTTP', 'High Entropy DGA', 'Dangling CNAME'],
        datasets: [{
          label: 'Flagged Instances',
          data: [34, 26, 19, 45, 22, 14],
          backgroundColor: [
            colors.red,
            '#FF7A00',
            colors.amber,
            colors.blue,
            colors.cyan,
            colors.green
          ],
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: colors.textColor, font: { size: 10 } }
          },
          y: {
            grid: { color: colors.gridColor },
            ticks: { color: colors.textColor }
          }
        }
      }
    });
  }
}

// Update charts when theme changes
window.addEventListener('sentrix-theme-changed', (e) => {
  const newTheme = e.detail.theme;
  const colors = getChartColors(newTheme);

  if (intelligenceRadarChart) {
    intelligenceRadarChart.data.datasets[0].backgroundColor = colors.radarBg;
    intelligenceRadarChart.data.datasets[0].borderColor = colors.radarBorder;
    intelligenceRadarChart.options.scales.r.grid.color = colors.gridColor;
    intelligenceRadarChart.options.scales.r.pointLabels.color = colors.textColor;
    intelligenceRadarChart.update();
  }

  if (riskDistributionChart) {
    riskDistributionChart.options.plugins.legend.labels.color = colors.textColor;
    riskDistributionChart.update();
  }

  if (activityTimelineChart) {
    activityTimelineChart.options.scales.x.ticks.color = colors.textColor;
    activityTimelineChart.options.scales.y.ticks.color = colors.textColor;
    activityTimelineChart.options.scales.y.grid.color = colors.gridColor;
    activityTimelineChart.update();
  }

  if (threatClassificationChart) {
    threatClassificationChart.options.scales.x.ticks.color = colors.textColor;
    threatClassificationChart.options.scales.y.ticks.color = colors.textColor;
    threatClassificationChart.options.scales.y.grid.color = colors.gridColor;
    threatClassificationChart.update();
  }
});

document.addEventListener('DOMContentLoaded', () => {
  initDashboardCharts();
});
