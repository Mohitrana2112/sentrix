/**
 * SENTRIX Main JavaScript Core
 * Theme switcher, mobile drawer, global search modal, toast notifications, clipboard utilities.
 */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Theme Management (Dark / Light)
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const savedTheme = localStorage.getItem('sentrix-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  updateThemeIcon(savedTheme);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', newTheme);
      localStorage.setItem('sentrix-theme', newTheme);
      updateThemeIcon(newTheme);
      showToast(`Switched to ${newTheme.toUpperCase()} mode`, 'info');
      // Dispatch custom event for charts to redraw theme colors
      window.dispatchEvent(new CustomEvent('sentrix-theme-changed', { detail: { theme: newTheme } }));
    });
  }

  function updateThemeIcon(theme) {
    if (!themeToggleBtn) return;
    const icon = themeToggleBtn.querySelector('i') || themeToggleBtn;
    if (theme === 'light') {
      themeToggleBtn.innerHTML = `<i data-lucide="moon"></i>`;
    } else {
      themeToggleBtn.innerHTML = `<i data-lucide="sun"></i>`;
    }
    if (window.lucide) lucide.createIcons();
  }

  // 2. Mobile Drawer Navigation Toggle
  const mobileToggleBtn = document.getElementById('mobileToggleBtn');
  const mobileNavDrawer = document.getElementById('mobileNavDrawer');
  if (mobileToggleBtn && mobileNavDrawer) {
    mobileToggleBtn.addEventListener('click', () => {
      mobileNavDrawer.classList.toggle('open');
    });
  }

  // 3. Global Search Modal (Ctrl + K / Cmd + K)
  const searchModal = document.getElementById('searchModal');
  const searchModalTriggers = document.querySelectorAll('.trigger-global-search');
  const closeSearchModalBtn = document.getElementById('closeSearchModalBtn');
  const globalSearchInput = document.getElementById('globalSearchInput');

  function openSearchModal() {
    if (searchModal) {
      searchModal.classList.add('open');
      if (globalSearchInput) {
        setTimeout(() => globalSearchInput.focus(), 100);
      }
    }
  }

  function closeSearchModal() {
    if (searchModal) {
      searchModal.classList.remove('open');
    }
  }

  searchModalTriggers.forEach(btn => btn.addEventListener('click', openSearchModal));
  if (closeSearchModalBtn) closeSearchModalBtn.addEventListener('click', closeSearchModal);

  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      if (searchModal && searchModal.classList.contains('open')) {
        closeSearchModal();
      } else {
        openSearchModal();
      }
    }
    if (e.key === 'Escape') {
      closeSearchModal();
    }
  });

  // Global search form redirection
  const globalModalForm = document.getElementById('globalModalForm');
  if (globalModalForm) {
    globalModalForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const query = (globalSearchInput.value || '').trim();
      if (!query) return;
      closeSearchModal();
      // Redirect to URL Analyzer or Domain Intel depending on input
      if (query.startsWith('http://') || query.startsWith('https://') || query.includes('/')) {
        window.location.href = `/url-analyzer?url=${encodeURIComponent(query)}`;
      } else {
        window.location.href = `/domain-intel?domain=${encodeURIComponent(query)}`;
      }
    });
  }

  // Initialize Lucide icons if available
  if (window.lucide) {
    lucide.createIcons();
  }
});

/**
 * Safe HTML Entity Escaping Utility
 */
window.escapeHtml = function(string) {
  const entityMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '/': '&#x2F;' };
  return String(string || '').replace(/[&<>"'\/]/g, s => entityMap[s]);
};

/**
 * Toast Notification System
 */
window.showToast = function(message, type = 'info') {
  let container = document.getElementById('toastContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  let iconName = 'info';
  let iconColor = 'var(--cyan-electric)';
  if (type === 'success') { iconName = 'check-circle'; iconColor = 'var(--success-green)'; }
  if (type === 'error') { iconName = 'alert-triangle'; iconColor = 'var(--danger-red)'; }
  if (type === 'warning') { iconName = 'alert-circle'; iconColor = 'var(--warning-amber)'; }

  toast.innerHTML = `
    <i data-lucide="${iconName}" style="color: ${iconColor}; width: 18px; height: 18px;"></i>
    <span>${message}</span>
  `;

  container.appendChild(toast);
  if (window.lucide) lucide.createIcons();

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
};

/**
 * Copy to Clipboard with Visual Feedback
 */
window.copyToClipboard = function(text, element = null) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    window.showToast('Copied to clipboard!', 'success');
    if (element) {
      const origHtml = element.innerHTML;
      element.innerHTML = `<i data-lucide="check" style="width:14px;height:14px;"></i> Copied!`;
      if (window.lucide) lucide.createIcons();
      setTimeout(() => {
        element.innerHTML = origHtml;
        if (window.lucide) lucide.createIcons();
      }, 2000);
    }
  }).catch(err => {
    window.showToast('Failed to copy to clipboard', 'error');
  });
};
