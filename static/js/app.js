'use strict';
const socket = io();

socket.on('audit_complete', (data) => {
    showToast(`Audit complete — Grade: ${data.grade} (Score: ${data.score}/100)`);
    setTimeout(() => location.reload(), 1500);
});

function showToast(msg) {
    const t = document.createElement('div');
    t.style.cssText = 'position:fixed;bottom:20px;right:20px;background:var(--accent);color:#0a0f1e;padding:12px 20px;border-radius:6px;font-size:.88em;font-weight:700;z-index:9999;max-width:350px;';
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 6000);
}

async function startAudit(event) {
    event.preventDefault();
    const url = document.getElementById('audit-url').value.trim();
    if (!url) return;
    const btn = document.getElementById('audit-btn');
    btn.textContent = 'Auditing...';
    btn.disabled = true;
    try {
        const resp = await fetch('/api/audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
        });
        const data = await resp.json();
        if (data.audit_id) {
            showToast('Audit started. Results will appear automatically.');
        }
    } catch (e) {
        showToast('Error starting audit');
    } finally {
        btn.textContent = 'Audit';
        btn.disabled = false;
    }
}
