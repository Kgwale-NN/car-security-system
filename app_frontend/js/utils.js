// ─── CONFIG ────────────────────────────────────────────────
const API_BASE = 'http://127.0.0.1:8000/api';
// ─── NAVIGATION HELPERS ────────────────────────────────────
function setActiveNav() {
  const path = window.location.pathname.split('/').pop();
  document.querySelectorAll('.nav-links a').forEach(link => {
    link.classList.remove('active');
    if (link.getAttribute('href') === path) link.classList.add('active');
  });
}

// ─── TOAST SYSTEM ──────────────────────────────────────────
function showToast(message, type = 'info', duration = 3500) {
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ─── API HELPERS ───────────────────────────────────────────
async function apiGet(endpoint) {
  try {
    const res = await fetch(`${API_BASE}${endpoint}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.error('GET error:', err);
    throw err;
  }
}

async function apiPost(endpoint, formData) {
  try {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      body: formData, // This sends the Face Image or PIN
    });
    const data = await res.json();
    return { ok: res.ok, data };
  } catch (err) {
    console.error('Connection error:', err);
    throw err;
  }
}

// ─── CAMERA UTILITIES ──────────────────────────────────────
async function startCamera(videoEl) {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ video: true });
    videoEl.srcObject = stream;
    await videoEl.play();
    return stream;
  } catch (err) {
    showToast('Camera access denied or not available', 'error');
    throw err;
  }
}

function stopCamera(stream) {
  if (stream) stream.getTracks().forEach(t => t.stop());
}

function captureFrame(videoEl, canvasEl) {
  const ctx = canvasEl.getContext('2d');
  canvasEl.width = videoEl.videoWidth;
  canvasEl.height = videoEl.videoHeight;
  ctx.drawImage(videoEl, 0, 0);
  return new Promise(resolve => canvasEl.toBlob(resolve, 'image/jpeg', 0.92));
}

// ─── FORMAT HELPERS ────────────────────────────────────────
function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-ZA', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
}

function timeAgo(iso) {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function statusBadge(status) {
  if (!status) return '';
  const s = status.toUpperCase();
  if (s === 'GRANTED') return `<span class="badge badge-granted">● GRANTED</span>`;
  if (s === 'DENIED') return `<span class="badge badge-denied">● DENIED</span>`;
  if (s === 'ACTIVE') return `<span class="badge badge-active">● ACTIVE</span>`;
  return `<span class="badge badge-warning">● ${s}</span>`;
}

// ─── SCANLINE ANIMATION ────────────────────────────────────
function startScanAnimation(el) {
  const line = document.createElement('div');
  line.style.cssText = `
    position:absolute; left:0; right:0; top:0; height:2px;
    background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent);
    animation: scan 1.8s linear infinite;
    pointer-events: none;
  `;
  el.style.position = 'relative';
  el.style.overflow = 'hidden';
  el.appendChild(line);
  return line;
}

// ─── INIT ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', setActiveNav);
