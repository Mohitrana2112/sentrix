/**
 * SENTRIX Advanced URL Analyzer Interactive Workspace
 * Live anatomy parsing, heuristic findings rendering, risk score meter.
 */

document.addEventListener('DOMContentLoaded', () => {
  const urlForm = document.getElementById('urlAnalysisForm');
  const urlInput = document.getElementById('targetUrlInput');
  const clearBtn = document.getElementById('clearUrlBtn');
  const scanningBar = document.getElementById('scanningIndicator');
  const resultsContainer = document.getElementById('analyzerResults');
  const emptyState = document.getElementById('analyzerEmptyState');

  // Check URL query parameters for auto-scan on load
  const urlParams = new URLSearchParams(window.location.search);
  const initialUrl = urlParams.get('url');
  if (initialUrl && urlInput) {
    urlInput.value = initialUrl;
    triggerUrlAnalysis(initialUrl);
  }

  // Sample URL chips click handler
  document.querySelectorAll('.sample-url-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const sample = chip.getAttribute('data-url');
      if (sample && urlInput) {
        urlInput.value = sample;
        triggerUrlAnalysis(sample);
      }
    });
  });

  if (clearBtn && urlInput) {
    clearBtn.addEventListener('click', () => {
      urlInput.value = '';
      if (resultsContainer) resultsContainer.style.display = 'none';
      if (emptyState) emptyState.style.display = 'block';
    });
  }

  if (urlForm) {
    urlForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const val = (urlInput.value || '').trim();
      if (!val) {
        window.showToast('Please enter a URL to inspect.', 'warning');
        return;
      }
      triggerUrlAnalysis(val);
    });
  }

  function escapeHtml(string) {
    if (typeof window.escapeHtml === 'function') return window.escapeHtml(string);
    const entityMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '/': '&#x2F;' };
    return String(string || '').replace(/[&<>"'\/]/g, s => entityMap[s]);
  }

  async function triggerUrlAnalysis(targetUrl) {
    if (scanningBar) scanningBar.classList.add('scanning-bar-active');
    if (emptyState) emptyState.style.display = 'none';

    let data;
    try {
      const response = await fetch('/api/analyze-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl })
      });

      if (!response.ok) {
        let errJson = {};
        try { errJson = await response.json(); } catch(e) {}
        throw new Error(errJson.error || `Server HTTP error: ${response.status}`);
      }

      data = await response.json();

    } catch (netErr) {
      if (scanningBar) scanningBar.classList.remove('scanning-bar-active');
      window.showToast(netErr.message || 'Unable to connect to analysis engine.', 'error');
      console.error('URL Analysis Network Error:', netErr);
      return;
    } finally {
      if (scanningBar) scanningBar.classList.remove('scanning-bar-active');
    }

    if (!data || !data.success) {
      window.showToast((data && data.error) ? data.error : 'Analysis failed.', 'error');
      return;
    }

    try {
      renderAnalysisResults(data);
      window.showToast('URL Analysis completed successfully.', 'success');

      // Update browser URL query parameter without reloading
      const newUrl = `${window.location.pathname}?url=${encodeURIComponent(targetUrl)}`;
      window.history.pushState({ path: newUrl }, '', newUrl);
    } catch (renderErr) {
      console.error('Render Analysis Results Error:', renderErr);
      window.showToast('Analysis completed with visual warnings.', 'warning');
    }
  }

  function renderAnalysisResults(data) {
    if (!resultsContainer) return;
    resultsContainer.style.display = 'block';

    const anat = data.anatomy;
    const risk = data.risk;
    const recs = data.recommendations;

    // 1. Anatomy Breakdown Elements
    document.getElementById('anatFullUrl').textContent = anat.full_url;
    document.getElementById('anatProtocol').textContent = anat.protocol + '://';
    document.getElementById('anatSubdomain').textContent = anat.subdomain || '(none)';
    document.getElementById('anatDomain').textContent = anat.domain;
    document.getElementById('anatTld').textContent = anat.tld;
    document.getElementById('anatPort').textContent = anat.port;
    document.getElementById('anatPath').textContent = anat.path;
    document.getElementById('anatFragment').textContent = anat.fragment;
    document.getElementById('anatEntropy').textContent = anat.host_entropy + ' bits/char';

    // Query params rendering
    const paramsListElem = document.getElementById('anatQueryParams');
    if (paramsListElem) {
      paramsListElem.innerHTML = '';
      const keys = Object.keys(anat.query_params);
      if (keys.length === 0) {
        paramsListElem.innerHTML = '<span style="color:var(--text-dim);">(No query parameters)</span>';
      } else {
        keys.forEach(k => {
          const pill = document.createElement('div');
          pill.className = 'quick-sample-chip';
          pill.style.display = 'inline-block';
          pill.style.margin = '2px';
          pill.innerHTML = `<strong>${k}</strong> = <code>${anat.query_params[k]}</code>`;
          paramsListElem.appendChild(pill);
        });
      }
    }

    // 2. Risk Meter & Classification
    const scoreValElem = document.getElementById('riskScoreValue');
    const riskClassElem = document.getElementById('riskClassificationBadge');
    const riskConfElem = document.getElementById('riskConfidenceBadge');
    const riskSummaryElem = document.getElementById('riskSummaryText');

    if (scoreValElem) scoreValElem.textContent = risk.score;
    if (riskSummaryElem) riskSummaryElem.textContent = risk.summary;

    if (riskClassElem) {
      riskClassElem.className = `risk-badge risk-badge-${risk.classification.toLowerCase()}`;
      riskClassElem.textContent = `${risk.classification} RISK`;
    }

    if (riskConfElem) {
      const conf = (risk.confidence || 'HIGH').toUpperCase();
      riskConfElem.className = `confidence-pill pill-${conf.toLowerCase()}`;
      riskConfElem.textContent = `${conf} CONFIDENCE`;
    }

    // Cache globally for AI Analyst and clipboard
    window.lastAnalyzedResult = data;
    window.currentAnalysisContext = data;

    // Quick action buttons setup
    const copyTargetBtn = document.getElementById('analyzerCopyTargetBtn');
    if (copyTargetBtn) {
      copyTargetBtn.onclick = () => window.copyToClipboard(data.url, copyTargetBtn);
    }

    const copyDomainBtn = document.getElementById('analyzerCopyDomainBtn');
    if (copyDomainBtn) {
      const dom = anat.registered_domain || anat.domain || '';
      copyDomainBtn.onclick = () => window.copyToClipboard(dom, copyDomainBtn);
    }

    const domainIntelLink = document.getElementById('analyzerDomainIntelLink');
    if (domainIntelLink) {
      const dom = anat.registered_domain || anat.domain || '';
      domainIntelLink.href = `/domain-intel?domain=${encodeURIComponent(dom)}`;
    }

    const askAiBtn = document.getElementById('analyzerAskAiBtn');
    if (askAiBtn) {
      askAiBtn.onclick = () => {
        const prompt = `Inspect analyzed URL ${data.url} (Score: ${risk.score}/100, Classification: ${risk.classification}). Explain why this score was assigned and what defensive steps SOC analysts should take.`;
        if (typeof window.openSentrixChatWithPrompt === 'function') {
          window.openSentrixChatWithPrompt(prompt);
        } else {
          const chatLauncher = document.getElementById('chatbotLauncherBtn');
          if (chatLauncher) chatLauncher.click();
          const chatInput = document.getElementById('chatbotInput');
          if (chatInput) {
            chatInput.value = prompt;
            chatInput.focus();
          }
        }
      };
    }

    // 2.5 IP Intelligence Dual-Stack Rendering
    const ipTableBody = document.getElementById('analyzerIpTableBody');
    const dnsBadge = document.getElementById('analyzerDnsBadge');
    const ipTimestamp = document.getElementById('analyzerIpTimestamp');
    const ipIntel = data.ip_intelligence || {};

    if (ipTimestamp && ipIntel.timestamp) {
      ipTimestamp.textContent = `DNS Lookup: ${ipIntel.timestamp}`;
    }

    if (dnsBadge) {
      const st = (ipIntel.status || 'RESOLVED').toUpperCase();
      dnsBadge.textContent = st;
      dnsBadge.className = st === 'RESOLVED' ? 'dns-status-pill pill-resolved' : 'dns-status-pill pill-unresolved';
    }

    if (ipTableBody) {
      ipTableBody.innerHTML = '';
      const ipDetails = ipIntel.details || ipIntel.ip_details || [];
      if (ipDetails.length === 0) {
        ipTableBody.innerHTML = `
          <tr>
            <td colspan="4" style="text-align:center; padding:1.2rem; color:var(--text-dim);">
              No resolved IP addresses for target (offline or unresolvable hostname).
            </td>
          </tr>
        `;
      } else {
        ipDetails.forEach(ipItem => {
          const tr = document.createElement('tr');
          tr.style.borderBottom = '1px solid var(--border-subtle)';

          let classTag = 'public';
          if (ipItem.is_private) classTag = 'private';
          else if (ipItem.is_loopback) classTag = 'loopback';
          else if (ipItem.is_reserved) classTag = 'reserved';

          const verStr = ipItem.version ? (String(ipItem.version).startsWith('IPv') ? ipItem.version : `IPv${ipItem.version}`) : 'IPv4';

          tr.innerHTML = `
            <td style="padding:0.45rem 0.3rem; font-family:var(--font-mono); font-weight:700; color:var(--text-main);">
              ${escapeHtml(ipItem.ip)}
            </td>
            <td style="padding:0.45rem 0.3rem; font-family:var(--font-mono); font-size:0.75rem; color:var(--text-dim);">
              ${escapeHtml(verStr)}
            </td>
            <td style="padding:0.45rem 0.3rem;">
              <span class="net-class-badge net-class-${classTag}">${escapeHtml(ipItem.classification || 'Public')}</span>
            </td>
            <td style="padding:0.45rem 0.3rem; font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted); word-break:break-all;">
              ${escapeHtml(ipItem.ptr || '(no PTR record)')}
            </td>
          `;
          ipTableBody.appendChild(tr);
        });
      }
    }

    const copyIpBtn = document.getElementById('analyzerCopyIpBtn');
    if (copyIpBtn) {
      const ips = ipIntel.all_addresses || ipIntel.all_ips || ipIntel.ipv4_addresses || ipIntel.ipv4 || [];
      if (ips.length > 0) {
        copyIpBtn.onclick = () => window.copyToClipboard(ips[0], copyIpBtn);
      }
    }

    // 3. Security Findings List
    const findingsListElem = document.getElementById('findingsListContainer');
    const indCountElem = document.getElementById('analyzerIndicatorCount');
    if (indCountElem) {
      indCountElem.textContent = `${risk.indicators.length} Finding${risk.indicators.length === 1 ? '' : 's'}`;
    }

    if (findingsListElem) {
      findingsListElem.innerHTML = '';
      if (risk.indicators.length === 0) {
        findingsListElem.innerHTML = `
          <div style="padding:1.5rem; text-align:center; color:var(--text-muted); background:var(--bg-surface-elevated); border-radius:12px; border:1px dashed var(--border-subtle);">
            <i data-lucide="shield-check" style="width:36px; height:36px; color:var(--success-green); margin-bottom:0.5rem;"></i>
            <p style="font-weight:700; color:var(--text-main); margin-bottom:0.25rem;">No High-Risk Anomalies Detected</p>
            <p style="font-size:0.8rem; color:var(--text-dim);">Standard protocol and clean syntax structure observed. Clean baseline score applied.</p>
          </div>
        `;
      } else {
        risk.indicators.forEach((ind) => {
          const item = document.createElement('div');
          item.className = 'live-indicator-card';
          item.style.marginBottom = '0.75rem';
          
          item.innerHTML = `
            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:0.35rem;">
              <div style="display:flex; align-items:center; gap:0.4rem;">
                <span class="sev-tag sev-${ind.severity.toLowerCase()}">${ind.severity}</span>
                <span style="font-size:0.9rem; font-weight:700; color:var(--text-main);">${escapeHtml(ind.name)}</span>
              </div>
              <span style="font-size:0.75rem; color:var(--text-dim); font-family:var(--font-mono); font-weight:700;">+${ind.score_impact} pts</span>
            </div>
            <div style="font-size:0.8rem; margin-bottom:0.35rem; color:var(--cyan-electric); font-family:var(--font-mono);">
              <strong>Evidence:</strong> ${escapeHtml(ind.evidence)}
            </div>
            <p style="font-size:0.8rem; color:var(--text-muted); margin-bottom:0.45rem; line-height:1.4;">
              ${escapeHtml(ind.technical_explanation)}
            </p>
            <div class="live-precaution-box">
              <strong style="color:var(--text-main);">Precaution:</strong> ${escapeHtml(ind.precaution)}
            </div>
          `;
          findingsListElem.appendChild(item);
        });
      }
    }

    // 4. Recommendations List
    const recsListElem = document.getElementById('recommendationsList');
    if (recsListElem) {
      recsListElem.innerHTML = '';
      if (recs.length === 0) {
        recsListElem.innerHTML = '<li style="color:var(--text-dim); font-size:0.8rem;">Standard defensive hygiene recommended.</li>';
      } else {
        recs.forEach(rec => {
          const li = document.createElement('li');
          li.className = 'live-rec-item';
          li.innerHTML = `<i data-lucide="check" style="width:13px;height:13px;color:var(--cyan-electric);flex-shrink:0;"></i> <span>${escapeHtml(rec)}</span>`;
          recsListElem.appendChild(li);
        });
      }
    }

    // Direct report download button link
    const pdfBtn = document.getElementById('downloadPdfBtn');
    if (pdfBtn && data.investigation_uuid) {
      pdfBtn.href = `/api/download-report/${data.investigation_uuid}?format=pdf`;
      pdfBtn.style.display = 'inline-flex';
    }

    if (window.lucide) lucide.createIcons();
  }
});
