/**
 * dashboard.js — WebShield client-side utilities
 */

/* Auto-dismiss flash alerts after 6 seconds */
document.addEventListener('DOMContentLoaded', () => {
  const alerts = document.querySelectorAll('.ws-alert');
  alerts.forEach(alert => {
    setTimeout(() => {
      const bsAlert = window.bootstrap?.Alert.getOrCreateInstance(alert);
      bsAlert?.close();
    }, 6000);
  });

  /* Highlight navbar link for current page */
  const path = window.location.pathname;
  document.querySelectorAll('.ws-navbar .nav-link').forEach(link => {
    const href = link.getAttribute('href');
    if (href && href !== '/' && path.startsWith(href)) {
      link.classList.add('active');
    }
  });
});

/* Scan form UX enhancement */
const mainScanForm = document.getElementById('mainScanForm');
if (mainScanForm) {
  mainScanForm.addEventListener('submit', function (e) {
    const urlInput = document.getElementById('urlInput');
    if (!urlInput) return;
    let val = urlInput.value.trim();
    if (val && !val.startsWith('http://') && !val.startsWith('https://')) {
      urlInput.value = 'https://' + val;
    }
  });
}

/* Score ring animation on page load */
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.ws-ring-fill').forEach(circle => {
    const currentDasharray = circle.getAttribute('stroke-dasharray');
    circle.setAttribute('stroke-dasharray', '0 213.6');
    setTimeout(() => {
      circle.style.transition = 'stroke-dasharray 1s ease';
      circle.setAttribute('stroke-dasharray', currentDasharray);
    }, 300);
  });
});
