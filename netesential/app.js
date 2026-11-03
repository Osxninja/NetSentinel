/**
 * NetSentinel Landing Webpage - Interactive Engine
 * Lead Developer: Hardik | Security Lab: Hidden Eye Security
 */

document.addEventListener('DOMContentLoaded', () => {
  initParticleCanvas();
  initTerminalSimulator();
  initArchitectureTabs();
  initOutlierCalculator();
  initCopyButtons();
});

/* ==========================================================================
   1. Interactive Particle Constellation Mesh
   ========================================================================== */
function initParticleCanvas() {
  const canvas = document.getElementById('bg-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  window.addEventListener('resize', () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  const particles = [];
  const particleCount = Math.min(Math.floor((width * height) / 18000), 75);

  for (let i = 0; i < particleCount; i++) {
    particles.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.45,
      vy: (Math.random() - 0.5) * 0.45,
      radius: Math.random() * 1.8 + 1,
      color: Math.random() > 0.4 ? 'rgba(0, 242, 254,' : 'rgba(168, 85, 247,'
    });
  }

  let mouse = { x: -1000, y: -1000 };
  window.addEventListener('mousemove', (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });

  function animate() {
    ctx.clearRect(0, 0, width, height);

    // Update & Draw Particles
    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0 || p.x > width) p.vx *= -1;
      if (p.y < 0 || p.y > height) p.vy *= -1;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = p.color + '0.7)';
      ctx.fill();

      // Connect lines
      for (let j = i + 1; j < particles.length; j++) {
        const p2 = particles[j];
        const dist = Math.hypot(p.x - p2.x, p.y - p2.y);
        if (dist < 130) {
          const alpha = (1 - dist / 130) * 0.22;
          ctx.strokeStyle = `rgba(0, 242, 254, ${alpha})`;
          ctx.lineWidth = 0.8;
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.stroke();
        }
      }

      // Mouse interaction
      const mouseDist = Math.hypot(p.x - mouse.x, p.y - mouse.y);
      if (mouseDist < 100) {
        ctx.strokeStyle = `rgba(0, 242, 254, ${1 - mouseDist / 100})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(p.x, p.y);
        ctx.lineTo(mouse.x, mouse.y);
        ctx.stroke();
      }
    }

    requestAnimationFrame(animate);
  }

  animate();
}

/* ==========================================================================
   2. Interactive Web Terminal Simulator
   ========================================================================== */
function initTerminalSimulator() {
  const terminalBody = document.getElementById('terminal-body');
  const terminalInput = document.getElementById('terminal-input');
  const presetChips = document.querySelectorAll('.preset-chip');

  if (!terminalBody || !terminalInput) return;

  function appendLine(html) {
    const div = document.createElement('div');
    div.className = 'term-line';
    div.innerHTML = html;
    terminalBody.appendChild(div);
    terminalBody.scrollTop = terminalBody.scrollHeight;
  }

  function handleCommand(cmdRaw) {
    const cmd = cmdRaw.trim().toLowerCase();
    appendLine(`<span class="term-prompt">netsentinel-cli&gt;</span> <span class="term-bold">${escapeHtml(cmdRaw)}</span>`);

    if (!cmd) return;

    if (cmd === 'help') {
      appendLine(`<span class="term-cyan">NetSentinel CLI Commands:</span>`);
      appendLine(`  <span class="term-yellow">status</span>     - Print live engine metrics, packet counts &amp; memory buffer.`);
      appendLine(`  <span class="term-yellow">alerts</span>     - List real-time detections with MITRE ATT&amp;CK techniques.`);
      appendLine(`  <span class="term-yellow">report</span>     - View autonomous (EC)² forensic incident report.`);
      appendLine(`  <span class="term-yellow">simulate</span>   - Inject synthetic attack pattern [scan|dos|exfil].`);
      appendLine(`  <span class="term-yellow">clear</span>      - Clear terminal screen.`);
    } else if (cmd === 'status') {
      appendLine(`<span class="term-green">[+] System Status: OPERATIONAL</span>`);
      appendLine(`  • Ingestion Mode: <span class="term-cyan">Dual (Scapy BPF + Zero-Privilege Fallback)</span>`);
      appendLine(`  • SQLite WAL State: <span class="term-cyan">Double-Buffered Async micro-batch (250 pkts / 500ms)</span>`);
      appendLine(`  • Total Packets Captured: <span class="term-bold">4,819</span> | Queue Buffer: <span class="term-green">0/10,000</span>`);
      appendLine(`  • Active Detections: <span class="term-red">3 High/Critical</span> | Reports Synthesized: <span class="term-purple">1 (EC)²</span>`);
    } else if (cmd === 'alerts') {
      appendLine(`<span class="term-yellow">Recent Incident Detections:</span>`);
      appendLine(`┌──────────┬─────────────────────┬──────────────────────────┬─────────────────────────────┐`);
      appendLine(`│ SEVERITY │ ENGINE              │ MITRE TECHNIQUE          │ TARGET FLOW                 │`);
      appendLine(`├──────────┼─────────────────────┼──────────────────────────┼─────────────────────────────┤`);
      appendLine(`│ <span class="term-red">CRITICAL</span> │ Stage 3 ML (IForest)│ T1041 Exfiltration C2    │ 192.168.1.100 -&gt; 10.0.0.5   │`);
      appendLine(`│ <span class="term-red">HIGH    </span> │ Stage 1 Heuristics  │ T1046 Network Discovery  │ 192.168.1.100 -&gt; 21 ports   │`);
      appendLine(`│ <span class="term-yellow">MEDIUM  </span> │ Stage 2 Stat MAD    │ T1498 Denial of Service  │ 192.168.1.100 (167.2 PPS)   │`);
      appendLine(`└──────────┴─────────────────────┴──────────────────────────┴─────────────────────────────┘`);
    } else if (cmd.startsWith('report')) {
      appendLine(`<span class="term-purple">╭──────────────── (EC)² Autonomous Forensic Incident Report ────────────────╮</span>`);
      appendLine(`<span class="term-bold">Target Incident:</span> Malicious Connection / Command &amp; Control Activity`);
      appendLine(`<span class="term-dim">Alert ID: df8fba54-9ffd-4c35-a713-cc43b8c9a593 | MITRE: T1041 Exfiltration</span>`);
      appendLine(`\n<span class="term-bold">Executive Narrative:</span>`);
      appendLine(`NetSentinel detected a CRITICAL payload transfer originating from 192.168.1.100.`);
      appendLine(`Multi-agent graph traversal verified host is a <span class="term-cyan">Finance Specialist Workstation</span>`);
      appendLine(`in VLAN 10 with NO authorized database connectivity to external endpoint 10.0.0.5.`);
      appendLine(`\n<span class="term-green">Recommended Actions:</span>`);
      appendLine(`• Immediately isolate 192.168.1.100 at switchport.`);
      appendLine(`• Revoke Active Directory Kerberos tickets for assigned user.`);
      appendLine(`• Block 10.0.0.5 on perimeter firewall.`);
      appendLine(`<span class="term-purple">╰───────────────────────────────────────────────────────────────────────────╯</span>`);
    } else if (cmd.startsWith('simulate')) {
      appendLine(`<span class="term-yellow">[!] Injecting synthetic attack cadence into pipeline...</span>`);
      setTimeout(() => {
        appendLine(`<span class="term-green">[✓] Injected: Rapid Port Scan Cadence against Server (T1046)</span>`);
        appendLine(`<span class="term-red">[ALERT TRIGGERED] Stage 1 Heuristic: 21 unique ports probed in 0.8s!</span>`);
        appendLine(`<span class="term-purple">[⚡] (EC)² Directed Graph Auto-Worker initiated investigation...</span>`);
      }, 500);
    } else if (cmd === 'clear') {
      terminalBody.innerHTML = '';
      return;
    } else {
      appendLine(`<span class="term-red">Command not recognized: '${escapeHtml(cmdRaw)}'. Type 'help' for options.</span>`);
    }
  }

  terminalInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const val = terminalInput.value;
      terminalInput.value = '';
      handleCommand(val);
    }
  });

  presetChips.forEach((chip) => {
    chip.addEventListener('click', () => {
      const cmd = chip.getAttribute('data-cmd');
      if (cmd) {
        handleCommand(cmd);
      }
    });
  });

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.innerText = text;
    return div.innerHTML;
  }
}

/* ==========================================================================
   3. Architecture Interactive Tabs
   ========================================================================== */
function initArchitectureTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  const panels = document.querySelectorAll('.tab-content-panel');

  tabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');

      tabBtns.forEach((b) => b.classList.remove('active'));
      panels.forEach((p) => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPanel = document.getElementById(targetId);
      if (targetPanel) {
        targetPanel.classList.add('active');
      }
    });
  });
}

/* ==========================================================================
   4. Interactive ML & MAD Outlier Visualizer
   ========================================================================== */
function initOutlierCalculator() {
  const slider = document.getElementById('calc-slider');
  const valDisplay = document.getElementById('calc-val');
  const zScoreDisplay = document.getElementById('calc-zscore');
  const ifScoreDisplay = document.getElementById('calc-ifscore');
  const statusBadge = document.getElementById('calc-status');

  if (!slider) return;

  const baselineMedian = 412;
  const baselineMAD = 128;

  function update() {
    const bytes = parseFloat(slider.value);
    if (valDisplay) valDisplay.textContent = bytes.toLocaleString() + ' B';

    // MAD Modified Z-Score: Mi = 0.6745 * |xi - median| / MAD
    const diff = Math.abs(bytes - baselineMedian);
    const zScore = (0.6745 * diff) / baselineMAD;

    if (zScoreDisplay) zScoreDisplay.textContent = zScore.toFixed(2);

    // Sigmoid ML score approx
    const ifScore = 1 / (1 + Math.exp(-0.0018 * (bytes - 1800)));
    if (ifScoreDisplay) ifScoreDisplay.textContent = (ifScore * 100).toFixed(0) + '%';

    if (statusBadge) {
      if (zScore > 3.5 || ifScore >= 0.70) {
        statusBadge.textContent = 'CRITICAL ANOMALY';
        statusBadge.className = 'badge-tag badge-red';
      } else if (zScore > 2.0 || ifScore >= 0.50) {
        statusBadge.textContent = 'ELEVATED SUSPICION';
        statusBadge.className = 'badge-tag badge-yellow';
      } else {
        statusBadge.textContent = 'NORMAL TRAFFIC';
        statusBadge.className = 'badge-tag badge-cyan';
      }
    }
  }

  slider.addEventListener('input', update);
  update();
}

/* ==========================================================================
   5. Copy to Clipboard
   ========================================================================== */
function initCopyButtons() {
  const copyButtons = document.querySelectorAll('.copy-btn, .btn-copy');

  copyButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const textToCopy = btn.getAttribute('data-copy') || 'git clone https://github.com/Osxninja/NetSentinel.git';
      navigator.clipboard.writeText(textToCopy).then(() => {
        const originalText = btn.innerHTML;
        btn.innerHTML = '<span>✓ Copied!</span>';
        setTimeout(() => {
          btn.innerHTML = originalText;
        }, 2000);
      });
    });
  });
}
