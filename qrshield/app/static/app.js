// QRshield Frontend Application Logic
let selectedFile = null;
let selectedFile2 = null;
let webcamStream = null;
let currentScanResult = null;

// Demo issuer private keys for offline demo execution
const DEMO_ISSUER_KEYS = {
  "citypark-01": "eHl6MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODk", // Demo seed private key
  "spit-admit": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY"
};

function switchTab(tabName) {
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));

  const targetTab = document.getElementById(`tab-${tabName}`);
  if (targetTab) targetTab.classList.add('active');

  const navBtns = document.querySelectorAll('.nav-btn');
  if (tabName === 'scanner') navBtns[0].classList.add('active');
  if (tabName === 'issuer') {
    navBtns[1].classList.add('active');
    onIssuerSelected();
  }
  if (tabName === 'admin') {
    navBtns[2].classList.add('active');
    loadAdminReports();
  }
}

function handleFileSelect(event) {
  const file = event.target.files[0];
  if (!file) return;
  selectedFile = file;

  const reader = new FileReader();
  reader.onload = (e) => {
    const preview = document.getElementById('img-preview');
    preview.src = e.target.result;
    document.getElementById('preview-box').style.display = 'block';
    document.getElementById('scan-btn').disabled = false;
    document.getElementById('scan-status').textContent = 'Image Ready';
  };
  reader.readAsDataURL(file);
}

function handleSecondFileSelect(event) {
  const file = event.target.files[0];
  if (!file) return;
  selectedFile2 = file;
  document.getElementById('scan-status').textContent = '2 Angles Ready';
  performScan();
}

async function toggleWebcam() {
  const video = document.getElementById('webcam');
  const webcamBox = document.getElementById('webcam-box');
  const webcamBtn = document.getElementById('webcam-btn');

  if (webcamStream) {
    webcamStream.getTracks().forEach(track => track.stop());
    webcamStream = null;
    webcamBox.style.display = 'none';
    webcamBtn.textContent = '🎥 Webcam';
    return;
  }

  try {
    webcamStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } }
    });
    video.srcObject = webcamStream;
    webcamBox.style.display = 'block';
    webcamBtn.textContent = '📸 Snap Frame';

    webcamBtn.onclick = captureWebcamFrame;
  } catch (err) {
    alert("Webcam access error: " + err.message);
  }
}

function captureWebcamFrame() {
  const video = document.getElementById('webcam');
  const canvas = document.createElement('canvas');
  canvas.width = video.videoWidth || 640;
  canvas.height = video.videoHeight || 480;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

  canvas.toBlob((blob) => {
    selectedFile = new File([blob], "camera_capture.png", { type: "image/png" });
    const preview = document.getElementById('img-preview');
    preview.src = canvas.toDataURL('image/png');
    document.getElementById('preview-box').style.display = 'block';
    document.getElementById('scan-btn').disabled = false;

    // Stop stream after capture
    if (webcamStream) {
      webcamStream.getTracks().forEach(track => track.stop());
      webcamStream = null;
      document.getElementById('webcam-box').style.display = 'none';
      const webcamBtn = document.getElementById('webcam-btn');
      webcamBtn.textContent = '🎥 Webcam';
      webcamBtn.onclick = toggleWebcam;
    }
    performScan();
  }, 'image/png');
}

async function performScan() {
  if (!selectedFile) return;

  const scanBtn = document.getElementById('scan-btn');
  const scanStatus = document.getElementById('scan-status');
  scanBtn.disabled = true;
  scanStatus.textContent = 'Analyzing...';

  const formData = new FormData();
  formData.append('image', selectedFile);
  if (selectedFile2) {
    formData.append('image2', selectedFile2);
  }

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      body: formData
    });
    const data = await res.json();
    currentScanResult = data;

    if (!data.success) {
      alert("Scan failed: " + (data.error || "Unable to decode QR code."));
      if (data.quality && data.quality.hints) {
        showQualityHints(data.quality.hints);
      }
      return;
    }

    renderScanVerdict(data);
  } catch (err) {
    alert("Network or scan API error: " + err.message);
  } finally {
    scanBtn.disabled = false;
    scanStatus.textContent = 'Completed';
  }
}

function renderScanVerdict(data) {
  document.getElementById('verdict-placeholder').style.display = 'none';
  document.getElementById('verdict-content').style.display = 'block';
  document.getElementById('scan-latency').textContent = `${data.elapsed_ms} ms`;

  const dec = data.decision;
  const layers = data.layers;

  // Banner
  const banner = document.getElementById('verdict-banner');
  banner.className = `verdict-banner ${dec.verdict}`;
  document.getElementById('verdict-text').textContent = dec.verdict;
  document.getElementById('verdict-risk').textContent = Number(dec.risk).toFixed(2);

  const iconMap = { SAFE: '🛡️', SUSPICIOUS: '⚠️', BLOCK: '⛔' };
  document.getElementById('verdict-icon').textContent = iconMap[dec.verdict] || '🛡️';

  // Certified badge
  const certBadge = document.getElementById('certified-badge');
  certBadge.style.display = dec.certified ? 'inline-flex' : 'none';

  // Reasons list
  const reasonsEl = document.getElementById('reasons-list');
  reasonsEl.innerHTML = '';
  (dec.reasons || []).forEach(r => {
    const li = document.createElement('li');
    li.textContent = r;
    reasonsEl.appendChild(li);
  });

  // Layer 1: URL ML
  const urlL = layers.url_layer;
  document.getElementById('url-score-pill').textContent = `Risk: ${Number(urlL.score).toFixed(2)}`;
  document.getElementById('url-type-badge').textContent = urlL.type || 'url';
  const urlSignalsEl = document.getElementById('url-signals');
  urlSignalsEl.innerHTML = '';
  (urlL.signals || []).forEach(s => {
    const li = document.createElement('li');
    li.textContent = s.text;
    urlSignalsEl.appendChild(li);
  });

  // Layer 2: CV Tamper
  const cvL = layers.cv_layer;
  document.getElementById('cv-score-pill').textContent = `Tamper: ${Number(cvL.score).toFixed(2)}`;
  document.getElementById('cv-status-badge').textContent = cvL.status;
  const cvSignalsEl = document.getElementById('cv-signals');
  cvSignalsEl.innerHTML = '';
  (cvL.signals || []).forEach(s => {
    const li = document.createElement('li');
    li.textContent = s.text;
    cvSignalsEl.appendChild(li);
  });

  // Inconclusive prompt handling (F21)
  const secondBox = document.getElementById('second-photo-box');
  if (cvL.status === 'inconclusive' && !selectedFile2) {
    secondBox.style.display = 'block';
  } else {
    secondBox.style.display = 'none';
  }

  // Grad-CAM heatmap overlay
  const heatmapBox = document.getElementById('heatmap-container');
  const heatmapImg = document.getElementById('heatmap-img');
  if (cvL.heatmap_png_b64) {
    heatmapImg.src = cvL.heatmap_png_b64;
    heatmapBox.style.display = 'block';
  } else {
    heatmapBox.style.display = 'none';
  }

  // Layer 3: Crypto PKI
  const sigL = layers.crypto_layer;
  const sigPill = document.getElementById('crypto-status-pill');
  sigPill.textContent = `Status: ${sigL.status.toUpperCase()}`;
  const cryptoDet = document.getElementById('crypto-details');

  if (sigL.status === 'valid') {
    sigPill.style.background = '#047857';
    sigPill.style.color = '#a7f3d0';
    cryptoDet.innerHTML = `
      <strong>Issuer:</strong> ${sigL.issuer.name}<br>
      <strong>Bound Domain:</strong> <code>${sigL.issuer.domain}</code><br>
      <strong>Key ID:</strong> ${sigL.issuer.key_id} | <strong>Location:</strong> ${sigL.issuer.location_id || 'N/A'}
    `;
  } else if (sigL.status === 'none') {
    sigPill.style.background = 'var(--bg-secondary)';
    sigPill.style.color = 'var(--text-muted)';
    cryptoDet.textContent = 'Unsigned QR code (falls back to URL ML & CV tamper layers).';
  } else {
    sigPill.style.background = '#991b1b';
    sigPill.style.color = '#fecaca';
    cryptoDet.innerHTML = `<span style="color:#f87171;">Cryptographic Alert:</span> Status is <strong>${sigL.status}</strong>.`;
  }

  // Safe Link interaction
  document.getElementById('decoded-payload').textContent = data.payload;
  const safetyConfirmBox = document.getElementById('safety-confirm-box');
  const confirmCheckbox = document.getElementById('confirm-open-checkbox');
  const openBtn = document.getElementById('open-link-btn');
  confirmCheckbox.checked = false;

  if (dec.verdict === 'SAFE') {
    safetyConfirmBox.style.display = 'none';
    openBtn.disabled = false;
    openBtn.style.opacity = '1';
  } else if (dec.verdict === 'SUSPICIOUS') {
    safetyConfirmBox.style.display = 'block';
    safetyConfirmBox.querySelector('label').textContent = '⚠️ Confirm: I wish to proceed despite suspicious indicators';
    openBtn.disabled = true;
    confirmCheckbox.onchange = () => { openBtn.disabled = !confirmCheckbox.checked; };
  } else {
    // BLOCK
    safetyConfirmBox.style.display = 'block';
    safetyConfirmBox.querySelector('label').textContent = '⛔ Danger: High risk detected. Check to unlock override';
    openBtn.disabled = true;
    confirmCheckbox.onchange = () => { openBtn.disabled = !confirmCheckbox.checked; };
  }
}

function handleOpenLink() {
  if (!currentScanResult || !currentScanResult.payload) return;
  const url = currentScanResult.payload;
  if (url.startsWith('http://') || url.startsWith('https://')) {
    window.open(url, '_blank', 'noopener,noreferrer');
  } else {
    alert("Payload: " + url);
  }
}

function showQualityHints(hints) {
  const el = document.getElementById('quality-hints');
  if (!hints || hints.length === 0) {
    el.style.display = 'none';
    return;
  }
  el.innerHTML = '<strong>Image Quality Hint:</strong> ' + hints.join(' ');
  el.style.display = 'block';
}

// User Report Feedback (F34)
function openReportModal() {
  document.getElementById('report-modal').style.display = 'flex';
}

function closeReportModal() {
  document.getElementById('report-modal').style.display = 'none';
}

async function submitFeedbackReport() {
  if (!currentScanResult) return;
  const label = document.getElementById('report-label').value;
  const note = document.getElementById('report-note').value;

  try {
    const res = await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scan_id: currentScanResult.scan_id,
        payload: currentScanResult.payload,
        user_label: label,
        note: note
      })
    });
    const json = await res.json();
    alert("Report submitted! Admin review queue updated.");
    closeReportModal();
  } catch (err) {
    alert("Submission error: " + err.message);
  }
}

// Issuer PKI Portal Logic (F27)
function onIssuerSelected() {
  const sel = document.getElementById('issuer-select').value;
  const urlInput = document.getElementById('issuer-url');
  if (sel === 'citypark-01') {
    urlInput.value = 'https://pay.citypark.example/m/42';
  } else {
    urlInput.value = 'https://spit.ac.in/departments/comps';
  }
}

async function generateSignedQR() {
  const issuerId = document.getElementById('issuer-select').value;
  const url = document.getElementById('issuer-url').value;
  const loc = document.getElementById('issuer-loc').value;
  const hours = parseInt(document.getElementById('issuer-validity').value) || 24;
  const privKey = DEMO_ISSUER_KEYS[issuerId] || "eHl6MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODk";

  try {
    const res = await fetch('/api/generate-signed-qr', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: url,
        issuer_id: issuerId,
        issuer_private_key_b64: privKey,
        location_id: loc,
        validity_hours: hours
      })
    });
    const data = await res.json();
    if (!data.success) {
      alert("Generation failed: " + data.detail);
      return;
    }
    const resultBox = document.getElementById('signed-qr-result');
    const qrImg = document.getElementById('signed-qr-img');
    const dlBtn = document.getElementById('download-qr-btn');
    const urlDisplay = document.getElementById('signed-url-display');

    qrImg.src = data.qr_png_base64;
    dlBtn.href = data.qr_png_base64;
    urlDisplay.textContent = data.signed_url;
    resultBox.style.display = 'block';
  } catch (err) {
    alert("Error: " + err.message);
  }
}

async function revokeCurrentIssuer() {
  const issuerId = document.getElementById('issuer-select').value;
  if (!confirm(`Are you sure you want to revoke key for '${issuerId}'? This will publish an updated root-signed CRL.`)) return;

  try {
    const res = await fetch(`/api/registry/issuers/${issuerId}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: "Emergency live demo revocation trigger" })
    });
    const data = await res.json();
    alert(`Issuer '${issuerId}' revoked! CRL Version is now: ${data.crl_version}. Subsequent scans will flag this token as REVOKED.`);
  } catch (err) {
    alert("Revocation error: " + err.message);
  }
}

// Admin Queue (F34, F35)
async function loadAdminReports() {
  try {
    const res = await fetch('/api/reports');
    const reports = await res.json();
    const tbody = document.getElementById('reports-table-body');
    tbody.innerHTML = '';

    if (reports.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 24px; color: var(--text-muted);">No reports pending review.</td></tr>';
      return;
    }

    reports.forEach(r => {
      const tr = document.createElement('tr');
      tr.style.borderBottom = '1px solid var(--border-color)';
      tr.innerHTML = `
        <td style="padding: 10px; font-family: var(--font-mono); font-size: 0.78rem;">${r.url}</td>
        <td style="padding: 10px; text-transform: uppercase; font-weight: 600;">${r.user_label}</td>
        <td style="padding: 10px; color: var(--text-muted);">${r.note || '-'}</td>
        <td style="padding: 10px;">
          <span style="padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; background: ${r.status === 'approved' ? '#065f46' : r.status === 'rejected' ? '#7f1d1d' : '#374151'};">
            ${r.status.toUpperCase()}
          </span>
        </td>
        <td style="padding: 10px;">
          <button onclick="reviewReport('${r.report_id}', 'approve')" style="background: #047857; color: white; border: none; padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; cursor: pointer; margin-right: 4px;">Approve</button>
          <button onclick="reviewReport('${r.report_id}', 'reject')" style="background: #991b1b; color: white; border: none; padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; cursor: pointer;">Reject</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load reports:", err);
  }
}

async function reviewReport(reportId, action) {
  try {
    await fetch(`/api/reports/${reportId}/review`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: action })
    });
    loadAdminReports();
  } catch (err) {
    alert("Review action failed: " + err.message);
  }
}

// 6 Scripted Scenarios from Section 13 Live Demo Plan
async function loadDemoScenario(num) {
  switchTab('scanner');
  document.getElementById('scan-status').textContent = `Loading Scenario ${num}...`;

  // Fetch pre-generated scenario image from server helper
  try {
    const res = await fetch(`/api/demo/scenario-image/${num}`);
    const blob = await res.blob();
    selectedFile = new File([blob], `scenario_${num}.png`, { type: 'image/png' });

    const reader = new FileReader();
    reader.onload = async (e) => {
      document.getElementById('img-preview').src = e.target.result;
      document.getElementById('preview-box').style.display = 'block';
      await performScan();

      if (num === 6) {
        // Guide user to feedback reporting modal
        setTimeout(() => {
          openReportModal();
          const noteField = document.getElementById('report-note');
          if (noteField) noteField.value = "Demo Scenario 6: Malicious KYC link flagged for retraining queue.";
        }, 500);
      }
    };
    reader.readAsDataURL(selectedFile);
  } catch (err) {
    alert("Error loading demo scenario: " + err.message);
  }
}

// Quick Custom URL / UPI Generator & Tester
async function generateAndScanCustomQR() {
  const input = document.getElementById('custom-qr-input');
  const text = (input ? input.value : "").trim();
  if (!text) {
    alert("Please enter a URL, UPI string, or text to generate and scan.");
    return;
  }
  switchTab('scanner');
  document.getElementById('scan-status').textContent = 'Generating QR...';
  try {
    const res = await fetch(`/api/demo/render-qr?text=${encodeURIComponent(text)}`);
    if (!res.ok) throw new Error("Failed to generate QR");
    const blob = await res.blob();
    selectedFile = new File([blob], "custom_test_qr.png", { type: 'image/png' });

    const reader = new FileReader();
    reader.onload = (e) => {
      document.getElementById('img-preview').src = e.target.result;
      document.getElementById('preview-box').style.display = 'block';
      performScan();
    };
    reader.readAsDataURL(selectedFile);
  } catch (err) {
    alert("Error generating custom QR: " + err.message);
  }
}

// Drag & Drop and Clipboard Paste (Ctrl+V) Support
document.addEventListener('DOMContentLoaded', () => {
  const dropZone = document.getElementById('drop-zone');
  if (dropZone) {
    ['dragenter', 'dragover'].forEach(eventName => {
      dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.add('drag-over');
      }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.remove('drag-over');
      }, false);
    });

    dropZone.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      const files = dt ? dt.files : null;
      if (files && files.length > 0) {
        handleFileSelect({ target: { files: [files[0]] } });
      }
    }, false);
  }

  // Paste image directly from clipboard (Ctrl+V)
  window.addEventListener('paste', (e) => {
    const items = (e.clipboardData || (e.originalEvent && e.originalEvent.clipboardData))?.items;
    if (!items) return;
    for (const item of items) {
      if (item.type.indexOf('image') === 0) {
        const file = item.getAsFile();
        if (file) {
          handleFileSelect({ target: { files: [file] } });
          break;
        }
      }
    }
  });
});
