    // Audio Context Synthesizer
    let audioCtx = null;
    let audioEnabled = true;

function playTacticalChirp(freq = 880, type = 'sawtooth', duration = 0.15) {
      if (!audioEnabled) return;
      try {
        if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = type;
        osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
        gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + duration);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start();
        osc.stop(audioCtx.currentTime + duration);
      } catch (e) {}
    }

function toggleAudio() {
      audioEnabled = !audioEnabled;
      document.getElementById('audio-label').innerText = audioEnabled ? "AUDIO: ON" : "AUDIO: OFF";
    }

    // Deck Switcher
function switchDeck(deck) {
      const ops = document.getElementById('deck-ops');
      const lab = document.getElementById('deck-lab');
      const cont = document.getElementById('deck-continuous');
      const auto = document.getElementById('deck-autopilot');
      const btnOps = document.getElementById('tab-btn-ops');
      const btnLab = document.getElementById('tab-btn-lab');
      const btnCont = document.getElementById('tab-btn-continuous');
      const btnAuto = document.getElementById('tab-btn-autopilot');

      ops.classList.add('hidden');
      lab.classList.add('hidden');
      cont.classList.add('hidden');
      auto.classList.add('hidden');
      btnOps.className = "px-4 py-1.5 font-bold border-b-2 border-transparent text-textMuted hover:text-white transition";
      btnLab.className = "px-4 py-1.5 font-bold border-b-2 border-transparent text-textMuted hover:text-white transition";
      btnCont.className = "px-4 py-1.5 font-bold border-b-2 border-transparent text-textMuted hover:text-white transition flex items-center gap-2";
      btnAuto.className = "px-4 py-1.5 font-bold border-b-2 border-transparent text-textMuted hover:text-white transition flex items-center gap-2";

      if (deck === 'ops') {
        ops.classList.remove('hidden');
        btnOps.className = "px-4 py-1.5 font-bold border-b-2 border-laserCyan text-laserCyan bg-laserCyan/5 transition";
      } else if (deck === 'lab') {
        lab.classList.remove('hidden');
        btnLab.className = "px-4 py-1.5 font-bold border-b-2 border-matrixGreen text-matrixGreen bg-matrixGreen/5 transition";
      } else if (deck === 'continuous') {
        cont.classList.remove('hidden');
        btnCont.className = "px-4 py-1.5 font-bold border-b-2 border-laserCyan text-laserCyan bg-laserCyan/5 transition flex items-center gap-2";
        resizeContinuousCanvases();
        renderOscilloscope();
        renderVelocityCanvas();
      } else if (deck === 'autopilot') {
        auto.classList.remove('hidden');
        btnAuto.className = "px-4 py-1.5 font-bold border-b-2 border-laserCyan text-laserCyan bg-laserCyan/5 transition flex items-center gap-2";
        opsRefresh();
      }
    }

    // Master Live Capture Toggle
    let isLiveSniffing = false;
async function toggleLiveCapture() {
      try {
        const res = await fetch("/api/sniff/toggle", { method: "POST" });
        const data = await res.json();
        updateCaptureUI(data.running);
      } catch (e) {
        console.error("Capture toggle failed:", e);
      }
    }

function updateCaptureUI(running) {
      isLiveSniffing = running;
      const btn = document.getElementById('master-capture-btn');
      const label = document.getElementById('master-capture-label');
      const text = document.getElementById('capture-status-text');
      const radarCircle = document.getElementById('radar-circle');
      const radarDot = document.getElementById('radar-indicator');

      if (running) {
        text.innerText = "ACTIVE (SNIFFING REAL NIC)";
        text.className = "text-xs font-bold text-laserCyan";
        if (label) label.innerText = "PAUSE LIVE SNIFF";
        btn.className = "ml-2 px-3 py-1 rounded text-xs font-bold font-mono tracking-wider transition flex items-center gap-2 bg-laserCyan/20 hover:bg-laserCyan/30 text-laserCyan border border-laserCyan/60 shadow-cyanGlow cursor-pointer";
        radarCircle.className = "w-6 h-6 rounded-full border border-laserCyan animate-ping";
        radarDot.className = "w-2 h-2 rounded-full bg-laserCyan shadow-cyanGlow";
      } else {
        text.innerText = "STANDBY (OFFLINE)";
        text.className = "text-xs font-bold text-slate-400";
        if (label) label.innerText = "ACTIVATE LIVE SNIFF";
        btn.className = "ml-2 px-3 py-1 rounded text-xs font-bold font-mono tracking-wider transition flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-600 cursor-pointer";
        radarCircle.className = "w-6 h-6 rounded-full border border-slate-700";
        radarDot.className = "w-2 h-2 rounded-full bg-slate-500";
      }
    }

    // Active Defense Toggle (Safe Audit vs Live Firewall Blocking)
async function toggleDefenseMode() {
      try {
        const res = await fetch("/api/defense/toggle", { method: "POST" });
        const data = await res.json();
        updateDefenseUI(data.active_defense);
        playTacticalChirp(data.active_defense ? 1000 : 500, 'sine', 0.15);
      } catch (e) {
        console.error("Defense toggle failed:", e);
      }
    }

function updateDefenseUI(active) {
      const pill = document.getElementById('defense-mode-pill');
      const label = document.getElementById('defense-mode-label');
      const dot = document.getElementById('defense-mode-dot');
      if (!pill) return;
      if (active) {
        if (label) label.innerText = "ACTIVE DEFENSE (REAL FIREWALL BLOCKS)";
        pill.className = "text-[10px] px-2 py-0.5 rounded bg-neonRed/20 hover:bg-neonRed/30 text-neonRed border border-neonRed/50 font-semibold tracking-wider transition cursor-pointer flex items-center gap-1.5 shadow-redGlow animate-pulse";
        if (dot) dot.className = "w-1.5 h-1.5 rounded-full bg-neonRed";
      } else {
        if (label) label.innerText = "ARMED (AUDIT / SAFE)";
        pill.className = "text-[10px] px-2 py-0.5 rounded bg-matrixGreen/10 hover:bg-matrixGreen/20 text-matrixGreen border border-matrixGreen/30 font-semibold tracking-wider transition cursor-pointer flex items-center gap-1.5";
        if (dot) dot.className = "w-1.5 h-1.5 rounded-full bg-matrixGreen";
      }
    }

    // Trigger Simulated Attacks
async function triggerSimulatedAttack(type) {
      try {
        playTacticalChirp(type === 'clean' ? 600 : 1200, 'square', 0.1);
        await fetch(`/api/simulate/${type}`, { method: "POST" });
      } catch (e) {
        console.error("Sim error:", e);
      }
    }

    // Manual Unban API
async function unbanIp(ip) {
      try {
        await fetch(`/api/bans/unban/${ip}`, { method: "POST" });
      } catch (e) {
        console.error("Unban error:", e);
      }
    }

    // Trigger Evolution Burst
let isEvolving = false;
async function triggerEvolutionBurst() {
      if (isEvolving) return; // re-entrancy guard: one burst at a time
      isEvolving = true;
      const btnLabel = document.getElementById('evolve-btn-label');
      btnLabel.innerText = "EVOLVING POPULATION...";
      try {
        await fetch("/api/training/evolve", { method: "POST" });
      } catch (e) {
        console.error("Evolution trigger error:", e);
        btnLabel.innerText = "EVOLVE 5 GENERATIONS";
        isEvolving = false;
      }
    }

    // ------------------------------------------------------------------
    // LIVING NEAT GENOME TOPOLOGY ENGINE (ANIMATED CANVAS)
    // ------------------------------------------------------------------
    const canvas = document.getElementById('neat-canvas');
    const ctx = canvas.getContext('2d');
    let particles = [];
    let genomeData = null;
    let inputActivations = new Array(20).fill(0.0);

    const SENSOR_LABELS = [
      "LEN", "PROTO", "SPORT", "DPORT",
      "SYN", "ACK", "FIN_RST", "PAYLOAD",
      "WIN", "TTL", "ΔT_IAT", "PPS_RATE",
      "ENTROPY", "NULL_SCAN", "XMAS_SCAN", "SYN_FIN",
      "URG", "PSH", "WIN_RATIO", "TTL_DIV"
    ];

function resizeCanvas() {
      canvas.width = canvas.parentElement.clientWidth;
      canvas.height = canvas.parentElement.clientHeight;
    }
    window.addEventListener('resize', resizeCanvas);

async function loadGenomeTopology() {
      try {
        const res = await fetch("/api/genome");
        genomeData = await res.json();
      } catch (e) {}
    }

function spawnSynapseImpulses(score) {
      if (!canvas.width) return;
      const numInputs = SENSOR_LABELS.length;
      const inputX = 60;
      const outputX = canvas.width - 60;
      const outputY = canvas.height / 2;

      for (let i = 0; i < numInputs; i++) {
        const inY = 24 + i * (canvas.height - 48) / (numInputs - 1);
        const act = inputActivations[i] || 0.1;
        // Spawn particle if sensor is excited
        if (act > 0.05 || Math.random() < 0.2) {
          particles.push({
            x: inputX,
            y: inY,
            startX: inputX,
            startY: inY,
            targetX: outputX,
            targetY: outputY,
            progress: 0,
            speed: 0.03 + Math.random() * 0.03,
            color: (score >= 0.85) ? '#ff003c' : '#00f0ff'
          });
        }
      }
    }

function renderNeuralCanvas() {
      if (!canvas.width) resizeCanvas();
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const numInputs = SENSOR_LABELS.length;
      const inputX = 60;
      const outputX = canvas.width - 60;
      const outputY = canvas.height / 2;

      // Draw Synaptic Connections
      for (let i = 0; i < numInputs; i++) {
        const inY = 24 + i * (canvas.height - 48) / (numInputs - 1);
        const isPos = (i % 2 === 0);
        ctx.strokeStyle = isPos ? "rgba(0, 240, 255, 0.15)" : "rgba(255, 0, 60, 0.15)";
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(inputX, inY);
        ctx.bezierCurveTo(inputX + 80, inY, outputX - 80, outputY, outputX, outputY);
        ctx.stroke();
      }

      // Update & Draw Synapse Impulse Particles
      for (let j = particles.length - 1; j >= 0; j--) {
        const p = particles[j];
        p.progress += p.speed;
        if (p.progress >= 1.0) {
          particles.splice(j, 1);
          continue;
        }
        // Bezier interpolation
        const t = p.progress;
        const cx1 = p.startX + 80;
        const cy1 = p.startY;
        const cx2 = p.targetX - 80;
        const cy2 = p.targetY;
        
        const px = Math.pow(1 - t, 3) * p.startX + 3 * Math.pow(1 - t, 2) * t * cx1 + 3 * (1 - t) * Math.pow(t, 2) * cx2 + Math.pow(t, 3) * p.targetX;
        const py = Math.pow(1 - t, 3) * p.startY + 3 * Math.pow(1 - t, 2) * t * cy1 + 3 * (1 - t) * Math.pow(t, 2) * cy2 + Math.pow(t, 3) * p.targetY;

        ctx.fillStyle = p.color;
        ctx.shadowColor = p.color;
        ctx.shadowBlur = 8;
        ctx.beginPath();
        ctx.arc(px, py, 2.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      // Draw Sensor Input Nodes with Labels & Activity Bars
      for (let i = 0; i < numInputs; i++) {
        const inY = 24 + i * (canvas.height - 48) / (numInputs - 1);
        const act = inputActivations[i] || 0.0;

        // Node Glow
        ctx.fillStyle = act > 0.5 ? "#00f0ff" : "#162032";
        ctx.beginPath();
        ctx.arc(inputX, inY, 4, 0, Math.PI * 2);
        ctx.fill();

        // Node Label
        ctx.fillStyle = act > 0.5 ? "#ffffff" : "#6b7994";
        ctx.font = "9px 'JetBrains Mono'";
        ctx.textAlign = "right";
        ctx.fillText(SENSOR_LABELS[i], inputX - 10, inY + 3);
      }

      // Draw Decision Core Output Node
      const currentScore = parseFloat(document.getElementById('gauge-number').innerText) || 0.0;
      const isThreat = currentScore >= 0.85;

      ctx.fillStyle = isThreat ? "#ff003c" : "#00ff88";
      ctx.shadowColor = isThreat ? "#ff003c" : "#00ff88";
      ctx.shadowBlur = isThreat ? 20 : 8;
      ctx.beginPath();
      ctx.arc(outputX, outputY, isThreat ? 10 : 7, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;

      // Core Label
      ctx.fillStyle = "#ffffff";
      ctx.font = "9px 'JetBrains Mono'";
      ctx.textAlign = "left";
      ctx.fillText("ANOMALY_CORE", outputX + 14, outputY + 3);

      requestAnimationFrame(renderNeuralCanvas);
    }

    // ------------------------------------------------------------------
    // TELEMETRY & ATTACK DOSSIER RENDERING
    // ------------------------------------------------------------------
    let activeBans = {};

function updateSpeedometer(score) {
      const arc = document.getElementById('gauge-arc');
      const num = document.getElementById('gauge-number');
      const badge = document.getElementById('threat-badge');
      const demonicBanner = document.getElementById('demonic-alert-banner');

      num.innerText = score.toFixed(4);

      // Dash offset: 235.6 is empty (0.0), 0 is full (1.0)
      const offset = 235.6 - (score * 235.6);
      arc.style.strokeDashoffset = offset;

      if (score >= 0.85) {
        arc.style.stroke = "#ff003c";
        num.style.fill = "#ff003c";
        badge.className = "px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-neonRed/20 text-neonRed border border-neonRed/50 animate-pulse";
        badge.innerText = "CRITICAL THREAT DETECTED";
        demonicBanner.classList.remove('hidden');
        playTacticalChirp(1400, 'sawtooth', 0.25);
      } else if (score >= 0.50) {
        arc.style.stroke = "#ffb703";
        num.style.fill = "#ffb703";
        badge.className = "px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-warningAmber/20 text-warningAmber border border-warningAmber/50";
        badge.innerText = "ELEVATED SUSPICION";
        demonicBanner.classList.add('hidden');
      } else {
        arc.style.stroke = "#00ff88";
        num.style.fill = "#ffffff";
        badge.className = "px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-matrixGreen/15 text-matrixGreen border border-matrixGreen/40";
        badge.innerText = "BASELINE NORMAL";
        demonicBanner.classList.add('hidden');
      }
    }

function updateAttackerDossier(pkt) {
      if (!pkt.intel) return;
      const i = pkt.intel;
      document.getElementById('dossier-ip').innerText = pkt.src;
      document.getElementById('dossier-geo').innerText = `${i.flag} ${i.country}, ${i.city}`;
      document.getElementById('dossier-asn').innerText = i.asn;
      document.getElementById('dossier-actor').innerText = i.threat_actor;
      document.getElementById('dossier-os').innerText = i.os_guess;
      document.getElementById('dossier-target').innerText = i.target_service;
      document.getElementById('dossier-seq').innerText = pkt.seq || '--';
      document.getElementById('dossier-ack').innerText = pkt.ack || '--';
      document.getElementById('dossier-win').innerText = pkt.window || '--';
      document.getElementById('dossier-ttl').innerText = pkt.ttl || '--';

      // C2 ThreatFox Match Indicator
      const c2Banner = document.getElementById('dossier-c2-banner');
      if (c2Banner) {
        if (i.c2_match || pkt.c2_match) {
          c2Banner.classList.remove('hidden');
          const c2Fam = document.getElementById('dossier-c2-family');
          if (c2Fam) c2Fam.innerText = i.malware_family || pkt.malware_family || i.threat_actor || 'Active Botnet / C2';
        } else {
          c2Banner.classList.add('hidden');
        }
      }

      // MITRE ATT&CK Mapping
      const mitre = i.mitre || pkt.mitre;
      if (mitre && mitre.id) {
        const mitreIdEl = document.getElementById('dossier-mitre-id');
        const mitreNameEl = document.getElementById('dossier-mitre-name');
        const mitreLinkEl = document.getElementById('dossier-mitre-link');
        if (mitreIdEl) mitreIdEl.innerText = mitre.id;
        if (mitreNameEl) mitreNameEl.innerText = mitre.name;
        if (mitreLinkEl) {
          mitreLinkEl.href = mitre.url;
          mitreLinkEl.title = `${mitre.id}: ${mitre.name} (Click to open MITRE ATT&CK Matrix)`;
        }
      }

      const hexEl = document.getElementById('dossier-hex');
      if (pkt.hex_dump && pkt.hex_dump !== "None (Pure Control Frame)") {
        hexEl.innerText = `${pkt.hex_dump}\n[ASCII]: ${pkt.ascii_dump}`;
      } else {
        hexEl.innerText = "-- Pure TCP Control Frame (Zero Payload) --";
      }
    }

function updateCouncilMeters(council) {
      if (!council) return;
      const brk = council.breakdown || {};
      const vol = brk.volumetric || 0;
      const rec = brk.recon || 0;
      const pay = brk.payload || 0;

      const volEl = document.getElementById('council-score-vol');
      const recEl = document.getElementById('council-score-rec');
      const payEl = document.getElementById('council-score-pay');
      const barVol = document.getElementById('council-bar-vol');
      const barRec = document.getElementById('council-bar-rec');
      const barPay = document.getElementById('council-bar-pay');
      const statVol = document.getElementById('council-vol-status');
      const statRec = document.getElementById('council-rec-status');
      const statPay = document.getElementById('council-pay-status');

      if (volEl) volEl.innerText = vol.toFixed(4);
      if (recEl) recEl.innerText = rec.toFixed(4);
      if (payEl) payEl.innerText = pay.toFixed(4);

      if (barVol) barVol.style.width = `${Math.min(100, Math.round(vol * 100))}%`;
      if (barRec) barRec.style.width = `${Math.min(100, Math.round(rec * 100))}%`;
      if (barPay) barPay.style.width = `${Math.min(100, Math.round(pay * 100))}%`;

      if (statVol) {
        statVol.innerText = vol >= 0.5 ? 'HOSTILE FLOOD' : 'NORMAL';
        statVol.className = vol >= 0.5 ? 'text-neonRed font-bold' : 'text-matrixGreen';
      }
      if (statRec) {
        statRec.innerText = rec >= 0.5 ? 'STEALTH SCAN' : 'NORMAL';
        statRec.className = rec >= 0.5 ? 'text-neonRed font-bold' : 'text-matrixGreen';
      }
      if (statPay) {
        statPay.innerText = pay >= 0.5 ? 'MALICIOUS PAYLOAD' : 'NORMAL';
        statPay.className = pay >= 0.5 ? 'text-neonRed font-bold' : 'text-matrixGreen';
      }

      const expEl = document.getElementById('council-leading-expert');
      const ruleEl = document.getElementById('council-consensus-rule');
      const modeBadge = document.getElementById('council-mode-badge');

      if (expEl && council.leading_expert) {
        expEl.innerText = council.leading_expert.replace(/_/g, ' ');
        expEl.className = (vol >= 0.5 || rec >= 0.5 || pay >= 0.5) ? 'text-neonRed font-bold ml-1' : 'text-white font-bold ml-1';
      }
      if (ruleEl && council.consensus_rule) {
        ruleEl.innerText = council.consensus_rule;
      }
      if (modeBadge && council.mode) {
        modeBadge.innerText = council.mode === 'MOE_COUNCIL' ? '3/3 SPECIALISTS ARBITRATING' : council.mode;
      }

      // Seat provenance: the held-out FPR that earned each specialist its
      // chair (recorded by train_honest.py's promotion gate). Written with
      // textContent only.
      const prov = council.seat_provenance || {};
      const provMap = { vol: prov.volumetric, rec: prov.recon, pay: prov.payload };
      for (const [slot, info] of Object.entries(provMap)) {
        const el = document.getElementById(`prov-${slot}`);
        if (!el) continue;
        const fpr = info && info.holdout_fpr;
        el.textContent = (typeof fpr === 'number')
          ? `FPR ${(fpr * 100).toFixed(2)}%`
          : 'FPR —';
        el.title = (info && info.seated)
          ? `Seated: holdout TPR ${((info.holdout_tpr ?? 0) * 100).toFixed(1)}% / FPR ${(fpr * 100).toFixed(2)}% cleared the promotion gate`
          : 'No holdout provenance recorded for this seat';
      }
      const provBox = document.getElementById('council-provenance');
      if (provBox) {
        const parts = [];
        for (const [role, info] of Object.entries(prov)) {
          if (role.startsWith('_') || !info || typeof info.holdout_fpr !== 'number') continue;
          const tpr = (typeof info.holdout_tpr === 'number') ? info.holdout_tpr : null;
          parts.push(`${role} ` + (tpr === null ? '' : `TPR ${(tpr * 100).toFixed(1)}% / `)
                    + `FPR ${(info.holdout_fpr * 100).toFixed(2)}%`);
        }
        const gate = prov._meta && prov._meta.holdout_gate_fpr;
        const gateTxt = (typeof gate === 'number') ? `holdout gate ${(gate * 100).toFixed(2)}% FPR` : 'holdout gate';
        provBox.textContent = parts.length
          ? `SEAT PROVENANCE (${gateTxt}): ` + parts.join('  ·  ')
          : '';
      }
    }

function renderBans(bans) {
      activeBans = bans || {};
      const tbody = document.getElementById('bans-table-body');
      const countEl = document.getElementById('active-bans-count');
      const ips = Object.keys(activeBans);
      countEl.innerText = `${ips.length} BANNED`;

      if (ips.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="p-3 text-center text-textMuted italic text-xs">No active host firewall blocks.</td></tr>`;
        return;
      }

      const now = Date.now() / 1000;
      let html = '';
      for (const ip of ips) {
        const item = activeBans[ip];
        const expireTs = typeof item === 'object' ? item.expire_ts : item;
        const flag = (typeof item === 'object' && item.flag) ? item.flag : '🚫';
        const country = (typeof item === 'object' && item.country) ? item.country : 'Hostile WAN';
        const remaining = Math.max(0, Math.floor(expireTs - now));
        const mins = Math.floor(remaining / 60);
        const secs = remaining % 60;
        const timeStr = `${mins}:${secs < 10 ? '0' : ''}${secs}`;

        html += `
          <tr class="hover:bg-panelLight/50 transition">
            <td class="p-2 font-bold text-laserCyan flex items-center gap-1.5">
              <span>${flag}</span> <span>${ip}</span>
            </td>
            <td class="p-2 text-slate-300">${country}</td>
            <td class="p-2 font-mono text-neonRed font-bold">${timeStr}</td>
            <td class="p-2 text-right">
              <button data-action="unban ip" data-ip="${ip}" class="px-2 py-0.5 rounded bg-slate-800 hover:bg-neonRed text-white text-[10px] font-mono border border-slate-700 transition">
                UNBAN
              </button>
            </td>
          </tr>
        `;
      }
      tbody.innerHTML = html;
    }

function addPacketRow(pkt) {
      const tbody = document.getElementById('packets-table-body');
      if (tbody.querySelector('td[colspan]')) tbody.innerHTML = '';

      const isThreat = pkt.score >= 0.85;
      const scoreColor = isThreat ? 'text-neonRed font-bold' : (pkt.score >= 0.5 ? 'text-warningAmber' : 'text-matrixGreen');
      const flag = pkt.intel ? pkt.intel.flag : '🌐';
      let actor = pkt.intel ? pkt.intel.threat_actor : 'LAN';
      if (pkt.c2_match || (pkt.intel && pkt.intel.c2_match)) {
        actor = `💀 [C2] ${pkt.malware_family || actor}`;
      }

      const row = document.createElement('tr');
      row.className = "hover:bg-panelLight cursor-pointer transition";
      row.onclick = () => openFeatureDrawer(pkt);
      row.innerHTML = `
        <td class="p-2 text-textMuted">${pkt.time}</td>
        <td class="p-2 font-bold text-laserCyan">${pkt.src}</td>
        <td class="p-2 text-slate-300">${pkt.dst}</td>
        <td class="p-2"><span class="px-1.5 py-0.5 rounded bg-void border border-panelBorder text-[10px] text-white">${pkt.flags}</span></td>
        <td class="p-2 font-mono ${scoreColor}">${pkt.score.toFixed(4)}</td>
        <td class="p-2 text-right text-[11px] text-slate-300">${flag} <span class="truncate max-w-[120px] inline-block align-bottom">${actor}</span></td>
      `;

      tbody.insertBefore(row, tbody.firstChild);
      while (tbody.children.length > 25) {
        tbody.removeChild(tbody.lastChild);
      }

      // Update HUD Gauges & Dossier
      updateSpeedometer(pkt.score);
      updateAttackerDossier(pkt);
      if (pkt.council) updateCouncilMeters(pkt.council);

      // Update Input Sensors for Neural Topology
      if (pkt.features) {
        inputActivations = Object.values(pkt.features);
        spawnSynapseImpulses(pkt.score);
      }
    }

function openFeatureDrawer(pkt) {
      const drawer = document.getElementById('feature-drawer');
      const label = document.getElementById('drawer-packet-label');
      const grid = document.getElementById('drawer-features-grid');
      drawer.classList.remove('hidden');

      label.innerText = `SRC: ${pkt.src} | FLAGS: ${pkt.flags} | ANOMALY: ${pkt.score.toFixed(4)}`;
      let html = '';
      for (const [key, val] of Object.entries(pkt.features || {})) {
        const isHighlight = (val > 0.5);
        html += `
          <div class="p-1.5 rounded bg-void border border-panelBorder flex justify-between">
            <span class="text-textMuted">${key}:</span>
            <span class="${isHighlight ? 'text-laserCyan font-bold' : 'text-slate-300'}">${typeof val === 'number' ? val.toFixed(3) : val}</span>
          </div>
        `;
      }
      grid.innerHTML = html;
    }

    // ------------------------------------------------------------------
    // REAL-TIME CONTINUOUS TELEMETRY & GRAPHING STATE
    // ------------------------------------------------------------------
    let scoreHistory = [];
    let velocityHistory = [];
    let continuousFitnessHistory = [];
    let isContinuousRunning = false;

function resizeContinuousCanvases() {
      const osc = document.getElementById('oscilloscope-canvas');
      if (osc && osc.parentElement) {
        osc.width = osc.parentElement.clientWidth;
        osc.height = osc.parentElement.clientHeight;
      }
      const vel = document.getElementById('cont-velocity-canvas');
      if (vel && vel.parentElement) {
        vel.width = vel.parentElement.clientWidth;
        vel.height = vel.parentElement.clientHeight;
      }
    }
    window.addEventListener('resize', resizeContinuousCanvases);

    // 1. REAL-TIME THREAT & ANOMALY OSCILLOSCOPE RENDERER
function renderOscilloscope() {
      const canvas = document.getElementById('oscilloscope-canvas');
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      const w = canvas.width;
      const h = canvas.height;
      if (!w || !h) return;

      ctx.fillStyle = "#05070a";
      ctx.fillRect(0, 0, w, h);

      // Grid lines
      ctx.strokeStyle = "#161c28";
      ctx.lineWidth = 1;
      [0.25, 0.50, 0.75, 1.0].forEach(lvl => {
        const y = h - (lvl * (h - 24)) - 12;
        ctx.beginPath();
        ctx.setLineDash([4, 4]);
        ctx.moveTo(35, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      });

      // 0.85 Threat Gate Line (Red dashed with glow)
      const yThresh = h - (0.85 * (h - 24)) - 12;
      ctx.save();
      ctx.strokeStyle = "rgba(255, 0, 60, 0.7)";
      ctx.lineWidth = 1.5;
      ctx.setLineDash([6, 3]);
      ctx.shadowColor = "#ff003c";
      ctx.shadowBlur = 8;
      ctx.beginPath();
      ctx.moveTo(35, yThresh);
      ctx.lineTo(w, yThresh);
      ctx.stroke();
      ctx.restore();

      ctx.setLineDash([]);
      ctx.font = "9px 'JetBrains Mono', monospace";
      ctx.fillStyle = "#ff003c";
      ctx.fillText("0.85 THREAT GATE", w - 105, yThresh - 4);

      // Y-axis labels
      ctx.fillStyle = "#6b7994";
      ctx.fillText("1.0", 8, 16);
      ctx.fillText("0.5", 8, h / 2);
      ctx.fillText("0.0", 8, h - 8);

      if (scoreHistory.length < 2) return;

      const padLeft = 38;
      const plotW = w - padLeft - 10;
      const n = scoreHistory.length;
      const step = plotW / Math.max(n - 1, 1);

      // Waveform line
      ctx.save();
      ctx.beginPath();
      ctx.lineWidth = 2;
      ctx.strokeStyle = "#00f0ff";
      ctx.shadowColor = "rgba(0, 240, 255, 0.5)";
      ctx.shadowBlur = 6;

      scoreHistory.forEach((pt, i) => {
        const x = padLeft + i * step;
        const y = h - (pt.score * (h - 24)) - 12;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
      ctx.restore();

      // Individual packet dots
      scoreHistory.forEach((pt, i) => {
        const x = padLeft + i * step;
        const y = h - (pt.score * (h - 24)) - 12;
        ctx.beginPath();
        if (pt.score >= 0.85) {
          ctx.arc(x, y, 4.5, 0, Math.PI * 2);
          ctx.fillStyle = "#ff003c";
          ctx.fill();
          ctx.strokeStyle = "#ffffff";
          ctx.lineWidth = 1;
          ctx.stroke();
        } else if (pt.score >= 0.5) {
          ctx.arc(x, y, 3, 0, Math.PI * 2);
          ctx.fillStyle = "#ffb703";
          ctx.fill();
        } else {
          ctx.arc(x, y, 2, 0, Math.PI * 2);
          ctx.fillStyle = "#00ff88";
          ctx.fill();
        }
      });
    }

    // 2. REAL-TIME VELOCITY CANVAS RENDERER
function renderVelocityCanvas() {
      const canvas = document.getElementById('cont-velocity-canvas');
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      const w = canvas.width;
      const h = canvas.height;
      if (!w || !h) return;

      ctx.fillStyle = "#05070a";
      ctx.fillRect(0, 0, w, h);

      ctx.strokeStyle = "#161c28";
      ctx.lineWidth = 1;
      ctx.setLineDash([2, 4]);
      for (let y = h - 20; y > 10; y -= 35) {
        ctx.beginPath();
        ctx.moveTo(35, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }
      ctx.setLineDash([]);

      if (velocityHistory.length < 2) return;

      const maxPPS = Math.max(...velocityHistory.map(v => v.pps), 20);
      const padLeft = 35;
      const plotW = w - padLeft - 10;
      const n = velocityHistory.length;
      const step = plotW / Math.max(n - 1, 1);

      // Area fill for PPS
      ctx.save();
      const grad = ctx.createLinearGradient(0, 0, 0, h);
      grad.addColorStop(0, "rgba(0, 240, 255, 0.35)");
      grad.addColorStop(1, "rgba(0, 240, 255, 0.0)");
      ctx.beginPath();
      velocityHistory.forEach((v, i) => {
        const x = padLeft + i * step;
        const y = h - ((v.pps / maxPPS) * (h - 26)) - 12;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.lineTo(padLeft + (n - 1) * step, h - 10);
      ctx.lineTo(padLeft, h - 10);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
      ctx.restore();

      // PPS line
      ctx.beginPath();
      ctx.strokeStyle = "#00f0ff";
      ctx.lineWidth = 2;
      velocityHistory.forEach((v, i) => {
        const x = padLeft + i * step;
        const y = h - ((v.pps / maxPPS) * (h - 26)) - 12;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }

    // 3. CONTINUOUS EVOLUTION CHART RENDERER
function renderContinuousEvolutionChart() {
      const bestLine = document.getElementById('cont-line-best');
      const avgLine = document.getElementById('cont-line-avg');
      const pointsG = document.getElementById('cont-chart-points');
      if (!bestLine || !avgLine || !pointsG) return;
      if (continuousFitnessHistory.length === 0) return;

      const minX = 40, maxX = 380;
      const minY = 170, maxY = 25;
      const n = continuousFitnessHistory.length;

      let bestPath = '';
      let avgPath = '';
      let pointsHtml = '';

      continuousFitnessHistory.forEach((pt, i) => {
        const x = n === 1 ? minX : minX + (i / (n - 1)) * (maxX - minX);
        // SSE fields can arrive null/undefined on transient backend states;
        // clamp to the baseline instead of emitting `M 50 NaN` path spam.
        const bf = Number.isFinite(Number(pt.best_fitness)) ? Number(pt.best_fitness) : 0;
        const af = Number.isFinite(Number(pt.avg_fitness)) ? Number(pt.avg_fitness) : 0;
        const yBest = minY - (bf * (minY - maxY));
        const yAvg = minY - (af * (minY - maxY));

        if (i === 0) {
          bestPath = `M ${x} ${yBest}`;
          avgPath = `M ${x} ${yAvg}`;
        } else {
          bestPath += ` L ${x} ${yBest}`;
          avgPath += ` L ${x} ${yAvg}`;
        }

        pointsHtml += `
          <circle cx="${x}" cy="${yBest}" r="3" fill="#00ff88" />
          <circle cx="${x}" cy="${yAvg}" r="2.5" fill="#00f0ff" />
        `;
      });

      bestLine.setAttribute('d', bestPath);
      avgLine.setAttribute('d', avgPath);
      pointsG.innerHTML = pointsHtml;

      const latest = continuousFitnessHistory[continuousFitnessHistory.length - 1];
      if (latest) {
        const bestTxt = typeof latest.best_fitness === 'number' ? latest.best_fitness.toFixed(4) : '--';
        document.getElementById('cont-chart-latest').innerText = `Cycle #${latest.cycle} Gen ${latest.generation} (Best: ${bestTxt})`;
        document.getElementById('cont-evolve-counter').innerText = `${continuousFitnessHistory.length} Generations Evolved`;
      }
    }

    // 4. PIPELINE STAGES ANIMATION
function updatePipelineStages(stage) {
      const label = document.getElementById('cont-pipeline-stage-label');
      if (label) label.innerText = `CURRENT STAGE: ${stage}`;

      const stages = {
        "SNIFFING": 1,
        "SAVING_PCAP": 1,
        "EXTRACTING_20D": 2,
        "RAY_EVOLUTION": 3,
        "HOLDOUT_VALIDATION": 4,
        "HOT_RELOAD": 4,
        "IDLE": 0
      };
      const activeNum = stages[stage] || 0;

      for (let i = 1; i <= 4; i++) {
        const box = document.getElementById(`pipe-stage-${i}`);
        const dot = document.getElementById(`pipe-dot-${i}`);
        if (!box || !dot) continue;

        if (i === activeNum) {
          box.className = "p-3.5 rounded bg-panelLight border-2 border-laserCyan shadow-cyanGlow transition-all duration-300 flex flex-col justify-between";
          dot.className = "w-2.5 h-2.5 rounded-full bg-laserCyan animate-ping";
        } else {
          box.className = "p-3.5 rounded bg-panelLight border border-panelBorder opacity-70 transition-all duration-300 flex flex-col justify-between";
          dot.className = "w-2 h-2 rounded-full bg-slate-600";
        }
      }
    }

    // 5. CONTINUOUS AUDIT CONSOLE
function addContinuousAuditLog(log) {
      const consoleEl = document.getElementById('cont-audit-console');
      if (!consoleEl) return;

      const stageColors = {
        "SAVE": "text-matrixGreen font-bold",
        "EXTRACT": "text-laserCyan font-bold",
        "RAY_EVOLVE": "text-warningAmber font-bold",
        "GATE": "text-purple-400 font-bold",
        "PROMOTE": "text-neonRed font-bold",
        "RETAIN": "text-slate-400 font-semibold",
        "CONTROL": "text-white font-bold",
        "INJECT": "text-laserCyan font-bold",
        "ERROR": "text-neonRed font-black"
      };

      const color = stageColors[log.stage] || "text-slate-300";
      // Built with textContent, not innerHTML: log messages can embed
      // exception text (e.g. IntelError details), which must never be
      // interpreted as markup inside the HUD.
      const row = document.createElement('div');
      row.className = "flex items-baseline gap-2";
      const ts = document.createElement('span');
      ts.className = "text-textMuted";
      ts.textContent = `[${log.time}]`;
      const st = document.createElement('span');
      st.className = color;
      st.textContent = `[${log.stage}]`;
      const msg = document.createElement('span');
      msg.className = "text-slate-200";
      msg.textContent = ` ${log.message}`;
      row.append(ts, st, msg);
      consoleEl.appendChild(row);
      consoleEl.scrollTop = consoleEl.scrollHeight;
    }

function clearContinuousAuditConsole() {
      const consoleEl = document.getElementById('cont-audit-console');
      if (consoleEl) consoleEl.innerHTML = '<div class="text-textMuted italic">[SYSTEM]: Continuous Audit Terminal cleared.</div>';
    }

    // 6. CONTINUOUS TOGGLE & INJECT HANDLERS
async function toggleContinuousLoop() {
      try {
        const res = await fetch("/api/continuous/toggle", { method: "POST" });
        const data = await res.json();
        updateContinuousUI(data);
      } catch (e) {
        console.error("Failed to toggle continuous loop:", e);
      }
    }

async function injectContinuousBatch() {
      try {
        await fetch("/api/continuous/inject_batch", { method: "POST" });
        playTacticalChirp(520, 'sine', 0.1);
      } catch (e) {
        console.error("Failed to inject batch:", e);
      }
    }

function updateContinuousUI(status) {
      isContinuousRunning = status.is_running;
      const ind = document.getElementById('cont-status-indicator');
      const badge = document.getElementById('cont-status-badge');
      const btn = document.getElementById('cont-toggle-btn');
      const label = document.getElementById('cont-toggle-label');
      const icon = document.getElementById('cont-toggle-icon');
      const tabDot = document.getElementById('tab-continuous-dot');

      if (status.is_running) {
        if (ind) ind.className = "w-3 h-3 rounded-full bg-matrixGreen animate-ping";
        if (badge) {
          badge.className = "px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-matrixGreen/20 text-matrixGreen border border-matrixGreen/50";
          badge.innerText = `ACTIVE (CYCLE #${status.cycle})`;
        }
        if (btn) {
          btn.className = "px-4 py-2 rounded text-xs font-mono font-bold tracking-wider transition flex items-center gap-2 bg-neonRed/20 hover:bg-neonRed/30 text-neonRed border border-neonRed/60 cursor-pointer shadow-sm";
        }
        if (label) label.innerText = "PAUSE CONTINUOUS LOOP";
        if (icon) icon.innerText = "⏸";
        if (tabDot) tabDot.className = "w-2 h-2 rounded-full bg-matrixGreen animate-pulse";
      } else {
        if (ind) ind.className = "w-3 h-3 rounded-full bg-slate-500";
        if (badge) {
          badge.className = "px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700";
          badge.innerText = "STANDBY / IDLE";
        }
        if (btn) {
          btn.className = "px-4 py-2 rounded text-xs font-mono font-bold tracking-wider transition flex items-center gap-2 bg-matrixGreen/20 hover:bg-matrixGreen/30 text-matrixGreen border border-matrixGreen/60 cursor-pointer shadow-sm";
        }
        if (label) label.innerText = "START CONTINUOUS LEARNING LOOP";
        if (icon) icon.innerText = "▶";
        if (tabDot) tabDot.className = "w-2 h-2 rounded-full bg-slate-500";
      }

      document.getElementById('cont-cycles').innerText = status.cycle;
      document.getElementById('cont-buffer').innerText = `${status.buffer_count} / ${status.buffer_threshold}`;
      document.getElementById('cont-saved-pkts').innerText = status.total_saved_packets;
      document.getElementById('cont-pcap-size').innerText = `${status.pcap_size_kb} KB`;
      document.getElementById('cont-promotions').innerText = status.champions_promoted;
      document.getElementById('cont-champ-fit').innerText = status.last_fitness ? status.last_fitness.toFixed(4) : "0.9980";

      updatePipelineStages(status.current_stage || (status.is_running ? "SNIFFING" : "IDLE"));
    }

    // ------------------------------------------------------------------
    // INITIALIZATION & SSE CONNECTION
    // ------------------------------------------------------------------
async function initHUD() {
      resizeCanvas();
      resizeContinuousCanvases();
      renderNeuralCanvas();
      await loadGenomeTopology();

      // System clock
      setInterval(() => {
        const now = new Date();
        document.getElementById('system-time').innerText = now.toTimeString().split(' ')[0];
        renderBans(activeBans);
      }, 1000);

      // Initial status fetch
      try {
        const res = await fetch("/api/status");
        const data = await res.json();
        document.getElementById('champ-fitness').innerText = data.fitness ? data.fitness.toFixed(4) : "0.9980";
        if (data.bans) renderBans(data.bans);
        if (data.live_sniffing !== undefined) updateCaptureUI(data.live_sniffing);
        if (data.active_defense !== undefined) updateDefenseUI(data.active_defense);
        if (data.council) updateCouncilMeters(data.council);
        updateAdversaryStats();
      } catch (e) {}

      // Fetch initial telemetry history & continuous status
      try {
        const histRes = await fetch("/api/telemetry/history");
        const histData = await histRes.json();
        if (histData.scores && histData.scores.length > 0) {
          scoreHistory = histData.scores;
          renderOscilloscope();
        }
        if (histData.velocity && histData.velocity.length > 0) {
          velocityHistory = histData.velocity;
          renderVelocityCanvas();
        }
        if (histData.continuous) {
          updateContinuousUI(histData.continuous);
        }
        if (histData.logs && histData.logs.length > 0) {
          histData.logs.forEach(l => addContinuousAuditLog(l));
        }
      } catch (e) {}

      // Fetch dynamic training stats for Deck 2
      updateTrainingStats();
      setInterval(updateTrainingStats, 5000);

      // Fetch Genetic Surgeon telemetry
      updateSurgeonStatus();
      setInterval(updateSurgeonStatus, 5000);

      // Connect SSE
      const evtSource = new EventSource("/api/stream");
      evtSource.onmessage = function(e) {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === "packet") {
            addPacketRow(msg.data);
            scoreHistory.push({
              time: msg.data.time,
              score: msg.data.score,
              src: msg.data.src,
              is_threat: msg.data.score >= 0.85
            });
            if (scoreHistory.length > 100) scoreHistory.shift();
            renderOscilloscope();
          } else if (msg.type === "bans") {
            renderBans(msg.data);
          } else if (msg.type === "defense_mode") {
            updateDefenseUI(msg.data.active_defense);
          } else if (msg.type === "velocity") {
            document.getElementById('velocity-pps').innerText = msg.data.pps;
            document.getElementById('velocity-kbps').innerText = msg.data.kbps.toFixed(1);
            document.getElementById('cont-live-pps').innerText = msg.data.pps;
            document.getElementById('cont-live-kbps').innerText = msg.data.kbps.toFixed(1);
            document.getElementById('total-packets-val').innerText = msg.data.total_packets;
            document.getElementById('total-threats-val').innerText = msg.data.total_threats;
            velocityHistory.push({
              time: msg.data.time || "",
              pps: msg.data.pps,
              kbps: msg.data.kbps
            });
            if (velocityHistory.length > 60) velocityHistory.shift();
            renderVelocityCanvas();
          } else if (msg.type === "continuous_status") {
            updateContinuousUI(msg.data);
          } else if (msg.type === "continuous_stage") {
            updatePipelineStages(msg.data.stage);
          } else if (msg.type === "continuous_progress") {
            document.getElementById('cont-buffer').innerText = `${msg.data.count} / ${msg.data.threshold}`;
            document.getElementById('cont-saved-pkts').innerText = msg.data.total_saved;
          } else if (msg.type === "continuous_save") {
            document.getElementById('cont-saved-pkts').innerText = msg.data.total_saved;
            document.getElementById('cont-pcap-size').innerText = `${msg.data.pcap_size_kb} KB`;
          } else if (msg.type === "continuous_evolve") {
            continuousFitnessHistory.push(msg.data);
            renderContinuousEvolutionChart();
          } else if (msg.type === "continuous_promote") {
            if (typeof msg.data.fitness === 'number') {
              document.getElementById('champ-fitness').innerText = msg.data.fitness.toFixed(4);
              document.getElementById('cont-champ-fit').innerText = msg.data.fitness.toFixed(4);
            }
            playTacticalChirp(1046, 'sine', 0.4);
          } else if (msg.type === "continuous_log") {
            addContinuousAuditLog(msg.data);
          } else if (msg.type === "evolution_update") {
            if (typeof msg.data.fitness === 'number') {
              document.getElementById('champ-fitness').innerText = msg.data.fitness.toFixed(4);
            }
            const _evoLog = document.getElementById('evolution-log');
            _evoLog.replaceChildren();
            const _evoTag = document.createElement('span');
            _evoTag.className = 'text-matrixGreen font-bold';
            _evoTag.textContent = '[EVOLUTION COMPLETE]:';
            const _evoMsg = document.createElement('span');
            _evoMsg.textContent = ' ' + String(msg.data.message);
            _evoLog.append(_evoTag, _evoMsg);
            document.getElementById('evolve-btn-label').innerText = "EVOLVE 5 GENERATIONS";
            isEvolving = false; // success or failure broadcast both release the button
            updateTrainingStats();
            playTacticalChirp(880, 'sine', 0.3);
          } else if (msg.type === "adversary_benchmark") {
            if (msg.data.benchmark && msg.data.benchmark.tiers) {
              renderAdversaryTiers(msg.data.benchmark.tiers);
              playTacticalChirp(880, 'sine', 0.4);
            }
          } else if (msg.type === "surgeon_intervention") {
            appendSurgeonLog(msg.data);
            updateSurgeonStatus();
            playTacticalChirp(880, 'triangle', 0.25);
          }
        } catch (err) {
          console.error("SSE parse error:", err);
        }
      };

      evtSource.onerror = function() {
        console.warn("SSE stream interrupted, reconnecting...");
      };
    }

async function updateTrainingStats() {
      try {
        const res = await fetch("/api/training/stats");
        const data = await res.json();
        if (data.evolution_history && data.evolution_history.length > 0) {
          renderFitnessChart(data.evolution_history);
        }
      } catch (e) {}
    }

function renderFitnessChart(history) {
      if (!history || history.length === 0) return;
      const bestLine = document.getElementById('chart-line-best');
      const avgLine = document.getElementById('chart-line-avg');
      if (!bestLine || !avgLine) return;

      const minX = 50, maxX = 460;
      const minY = 180, maxY = 20;

      const n = history.length;
      let bestPath = '';
      let avgPath = '';

      history.forEach((pt, i) => {
        const x = n === 1 ? minX : minX + (i / (n - 1)) * (maxX - minX);
        // Honest training logs store null fitness for unmeasured generations;
        // clamp to baseline rather than emit `M 50 NaN` path spam.
        const bf = Number.isFinite(Number(pt.best_fitness)) ? Number(pt.best_fitness) : 0;
        const af = Number.isFinite(Number(pt.avg_fitness)) ? Number(pt.avg_fitness) : 0;
        const yBest = minY - (bf * (minY - maxY));
        const yAvg = minY - (af * (minY - maxY));

        if (i === 0) {
          bestPath = `M ${x} ${yBest}`;
          avgPath = `M ${x} ${yAvg}`;
        } else {
          bestPath += ` L ${x} ${yBest}`;
          avgPath += ` L ${x} ${yAvg}`;
        }
      });

      bestLine.setAttribute('d', bestPath);
      avgLine.setAttribute('d', avgPath);
    }

    // ------------------------------------------------------------------
    // ADVERSARIAL RED TEAM SPARRING & STRESS TEST FUNCTIONS
    // ------------------------------------------------------------------
async function updateAdversaryStats() {
      try {
        const res = await fetch("/api/adversary/stats");
        const data = await res.json();
        if (data.hall_of_fame_count !== undefined) {
          const hofEl = document.getElementById('adv-hof-count');
          if (hofEl) hofEl.innerText = `${data.hall_of_fame_count} Champions Stored`;
        }
        if (data.benchmark && data.benchmark.tiers) {
          renderAdversaryTiers(data.benchmark.tiers);
        }
      } catch (e) {}
    }

function renderAdversaryTiers(tiers) {
      if (!tiers || tiers.length < 5) return;
      const ids = ['adv-t0', 'adv-t1', 'adv-t2', 'adv-t3', 'adv-t4'];
      tiers.forEach((t, idx) => {
        if (idx < ids.length) {
          const prefix = ids[idx];
          const rateEl = document.getElementById(`${prefix}-rate`);
          const barEl = document.getElementById(`${prefix}-bar`);
          if (rateEl) {
            const fprPart = (typeof t.moe_fpr === 'number') ? ` · ${t.moe_fpr.toFixed(1)}% FP` : '';
            rateEl.innerText = `${t.moe_detection.toFixed(1)}% Det${fprPart}`;
            rateEl.className = t.moe_detection >= 90 ? 'font-bold text-matrixGreen' : (t.moe_detection >= 75 ? 'font-bold text-warningAmber' : 'font-bold text-neonRed');
          }
          if (barEl) {
            barEl.style.width = `${Math.min(100, Math.round(t.moe_detection))}%`;
          }
        }
      });
    }

async function runAdversaryStressTest() {
      const btn = document.getElementById('adv-stress-btn');
      const text = document.getElementById('adv-btn-text');
      if (btn) btn.disabled = true;
      if (text) text.innerText = "RUNNING 5-TIER ADVERSARIAL BENCHMARK...";
      playTacticalChirp(660, 'square', 0.2);

      try {
        const res = await fetch("/api/adversary/stress_test", { method: "POST" });
        const data = await res.json();
        if (data.benchmark && data.benchmark.tiers) {
          renderAdversaryTiers(data.benchmark.tiers);
          playTacticalChirp(880, 'sine', 0.4);
        }
      } catch (err) {
        console.error("Adversary stress test failed:", err);
      } finally {
        if (btn) btn.disabled = false;
        if (text) text.innerText = "RUN FULL-SPECTRUM ADVERSARIAL STRESS TEST";
      }
    }

    // ------------------------------------------------------------------
    // GENETIC SURGEON (META-LEARNING DIRECTED MUTATION) FUNCTIONS
    // ------------------------------------------------------------------
function appendSurgeonLog(data) {
      const consoleEl = document.getElementById('surgeon-log-console');
      if (!consoleEl) return;

      const ts = data.timestamp || new Date().toTimeString().split(' ')[0];
      let html = '';
      if (!data.interventions || data.interventions.length === 0) {
        html = `<div class="text-matrixGreen">[${ts}] 🔬 DIAGNOSIS CLEAR: Accuracy ${(data.accuracy !== undefined ? (data.accuracy * 100).toFixed(1) : "100.0")}% &bull; Pre-FN: ${data.pre_fn || 0}, Pre-FP: ${data.pre_fp || 0} (Optimal topology)</div>`;
      } else {
        data.interventions.forEach(item => {
          html += `<div class="text-amber-300">[${ts}] <span class="text-amber-400 font-bold">⚡ ${item.action || 'SPLICED'}</span>: Sensor <strong>${item.sensor_name || 'Node ' + item.sensor_node}</strong> &rarr; Target Node ${item.target_node} (w=${item.weight ? item.weight.toFixed(2) : '+2.0'}) &bull; <span class="text-slate-400">${item.rationale || ''}</span></div>`;
        });
      }
      consoleEl.innerHTML += html;
      consoleEl.scrollTop = consoleEl.scrollHeight;
    }

async function updateSurgeonStatus() {
      try {
        const res = await fetch("/api/surgeon/status");
        const data = await res.json();
        const totalEl = document.getElementById('surgeon-total-count');
        const statusEl = document.getElementById('surgeon-status-val');
        if (totalEl && data.total_surgeries !== undefined) {
          totalEl.innerText = data.total_surgeries;
        }
        if (statusEl && data.status) {
          statusEl.innerText = data.status.toUpperCase() === "READY" ? "HEURISTIC READY" : data.status.toUpperCase();
        }
        if (data.recent_interventions && data.recent_interventions.length > 0) {
          const consoleEl = document.getElementById('surgeon-log-console');
          if (consoleEl && consoleEl.dataset.initialized !== "true") {
            consoleEl.innerHTML = '';
            data.recent_interventions.forEach(entry => {
              const ts = entry.timestamp ? entry.timestamp.split('T')[1].slice(0, 8) : '--:--:--';
              if (!entry.interventions || entry.interventions.length === 0) {
                const _diag = document.createElement('div');
                _diag.className = 'text-slate-400';
                _diag.textContent = `[${ts}] Diagnostic baseline: Accuracy ${(entry.pre_accuracy * 100).toFixed(1)}% (FN: ${entry.pre_fn}, FP: ${entry.pre_fp})`;
                consoleEl.append(_diag);
              } else {
                entry.interventions.forEach(op => {
                  const _op = document.createElement('div');
                  _op.className = 'text-amber-300';
                  const _tag = document.createElement('span');
                  _tag.className = 'text-amber-400 font-bold';
                  _tag.textContent = `[${ts}] ⚡ ${op.action}`;
                  // Render per-action, not per-shape: a bias recalibration
                  // has no sensor/weight fields, a graft has no bias fields.
                  const _detail = document.createElement('span');
                  if (op.action === 'RECALIBRATED_OUTPUT_BIAS') {
                    const ob = (typeof op.old_bias === 'number') ? op.old_bias.toFixed(2) : '--';
                    const nb = (typeof op.new_bias === 'number') ? op.new_bias.toFixed(2) : '--';
                    _detail.textContent = `: output bias ${ob} → ${nb}`;
                  } else if (op.action === 'GRAFTED_INTERMEDIARY_NODE') {
                    _detail.textContent = `: node #${op.node_id} (${op.activation || 'relu'}) from sensor ${op.sensor_source}`;
                  } else {
                    const w = (typeof op.weight === 'number') ? op.weight.toFixed(2) : '--';
                    _detail.textContent = `: ${op.sensor_name || op.sensor_node} → Node ${op.target_node} (w=${w})`;
                  }
                  _op.append(_tag, _detail);
                  consoleEl.append(_op);
                });
              }
            });
            consoleEl.dataset.initialized = "true";
            consoleEl.scrollTop = consoleEl.scrollHeight;
          }
        }
      } catch (e) {}
    }

async function triggerDirectedSurgery() {
      const btn = document.getElementById('surgeon-op-btn');
      const text = document.getElementById('surgeon-btn-text');
      if (btn) btn.disabled = true;
      if (text) text.innerText = "PERFORMING GENETIC DIAGNOSIS & DIRECTED SPLICING...";
      playTacticalChirp(600, 'square', 0.15);

      try {
        const res = await fetch("/api/surgeon/operate", { method: "POST" });
        const json = await res.json();
        if (json.data) {
          appendSurgeonLog(json.data);
          await updateSurgeonStatus();
          playTacticalChirp(950, 'sine', 0.35);
        }
      } catch (err) {
        console.error("Surgeon operation failed:", err);
      } finally {
        if (btn) btn.disabled = false;
        if (text) text.innerText = "TRIGGER DIRECTED SURGERY ON CANDIDATE GENOME";
      }
    }

    window.onload = initHUD;
  
    // =====================================================================
    // DECK 4: OPS & AUTOMATION
    //
    // Polling only runs while this deck is the visible one and the page itself
    // is visible. A background tab or another deck should not be waking the
    // machine to re-read the archive every few seconds.
    // =====================================================================
    const OPS_TAG_HINTS = {};
    let opsPollTimer = null;
    let opsActiveJob = null;

function opsDeckVisible() {
      const deck = document.getElementById('deck-autopilot');
      return deck && !deck.classList.contains('hidden')
             && document.visibilityState === 'visible';
    }

function opsSay(message) {
      const live = document.getElementById('ops-live');
      if (live) live.textContent = message;
    }

function opsBusy(btn, busy, busyLabel) {
      if (!btn) return;
      if (busy) {
        if (!btn.dataset.idleLabel) btn.dataset.idleLabel = btn.textContent.trim();
        btn.disabled = true;
        btn.setAttribute('aria-busy', 'true');
        btn.textContent = busyLabel || 'WORKING…';
      } else {
        btn.disabled = false;
        btn.removeAttribute('aria-busy');
        if (btn.dataset.idleLabel) btn.textContent = btn.dataset.idleLabel;
      }
    }

async function opsLoadTags() {
      try {
        const res = await fetch('/api/ops/tags');
        const { tags } = await res.json();
        const sel = document.getElementById('rolling-tag');
        if (!sel || sel.options.length) return;
        for (const t of tags) {
          OPS_TAG_HINTS[t.tag] = t.label;
          const opt = document.createElement('option');
          opt.value = t.tag;
          opt.textContent = t.tag;
          if (t.tag === 'mixed') opt.selected = true;
          sel.appendChild(opt);
        }
        sel.addEventListener('change', opsShowTagHint);
        opsShowTagHint();
      } catch (e) { /* dashboard may still be starting */ }
    }

function opsShowTagHint() {
      const sel = document.getElementById('rolling-tag');
      const hint = document.getElementById('rolling-tag-hint');
      if (sel && hint) hint.textContent = OPS_TAG_HINTS[sel.value] || '';
    }

async function opsRollingStart() {
      const btn = document.getElementById('btn-rolling-start');
      const tag = document.getElementById('rolling-tag').value;
      const mins = parseInt(document.getElementById('rolling-minutes').value, 10) || 15;
      opsBusy(btn, true, 'STARTING…');
      try {
        const res = await fetch('/api/ops/rolling/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ tag, chunk_minutes: mins })
        });
        const data = await res.json();
        if (!res.ok) {
          document.getElementById('rolling-detail').textContent = data.error || 'start failed';
          opsSay('Capture failed to start.');
        } else {
          opsSay(`Rolling capture started, context ${tag}.`);
        }
      } catch (e) {
        document.getElementById('rolling-detail').textContent = String(e);
      } finally {
        opsBusy(btn, false);
        opsRefresh();
      }
    }

async function opsRollingStop() {
      const btn = document.getElementById('btn-rolling-stop');
      opsBusy(btn, true, 'STOPPING…');
      try {
        const res = await fetch('/api/ops/rolling/stop', { method: 'POST' });
        const data = await res.json();
        document.getElementById('rolling-detail').textContent =
          data.note || data.error || '';
        opsSay('Capture will stop after the current chunk is written.');
      } catch (e) {
        document.getElementById('rolling-detail').textContent = String(e);
      } finally {
        opsBusy(btn, false);
        opsRefresh();
      }
    }

async function opsJob(key) {
      const btn = document.getElementById(`btn-job-${key}`);
      const tail = document.getElementById('job-tail');
      opsBusy(btn, true, 'RUNNING…');
      document.getElementById('job-verdict').textContent = '';
      tail.textContent = `starting ${key}…`;
      try {
        const res = await fetch(`/api/ops/job/${key}`, { method: 'POST' });
        const data = await res.json();
        if (!res.ok) {
          tail.textContent = data.error || 'failed to start';
          opsBusy(btn, false);
          return;
        }
        opsActiveJob = key;
        opsSay(`${key} started.`);
        opsPollJob(key, btn);
      } catch (e) {
        tail.textContent = String(e);
        opsBusy(btn, false);
      }
    }

async function opsPollJob(key, btn) {
      try {
        const res = await fetch(`/api/ops/job/${key}`);
        const data = await res.json();
        const tail = document.getElementById('job-tail');
        tail.textContent = (data.tail || []).join('\n') || 'no output yet';
        tail.scrollTop = tail.scrollHeight;
        if (data.running) {
          setTimeout(() => opsPollJob(key, btn), 2000);
          return;
        }
        opsActiveJob = null;
        opsBusy(btn, false);
        const v = document.getElementById('job-verdict');
        const verdict = data.verdict || (data.exit_code === 0 ? 'DONE' : `EXIT ${data.exit_code}`);
        const colour = verdict === 'PASS' || verdict === 'DONE' ? 'text-matrixGreen'
                     : verdict === 'WARN' ? 'text-amber-400' : 'text-crimson';
        v.className = `font-bold ${colour}`;
        v.textContent = verdict;
        opsSay(`${key} finished: ${verdict}.`);
        opsRefresh();
      } catch (e) {
        opsBusy(btn, false);
      }
    }

async function opsInstallSchedule() {
      const btn = document.getElementById('btn-schedule-install');
      const detail = document.getElementById('schedule-detail');
      opsBusy(btn, true, 'REGISTERING…');
      try {
        const res = await fetch('/api/ops/schedule/install', { method: 'POST' });
        const data = await res.json();
        if (!res.ok) {
          detail.textContent = data.error || 'failed';
        } else if (data.all_installed) {
          detail.textContent = 'Both tasks registered. Windows will run them whether or not the dashboard is open.';
          opsSay('Scheduled tasks registered.');
        } else {
          detail.textContent = (data.failures || []).join(' · ') + (data.hint ? ' — ' + data.hint : '');
          opsSay('Scheduled task registration failed.');
        }
      } catch (e) {
        detail.textContent = String(e);
      } finally {
        opsBusy(btn, false);
        opsRefresh();
      }
    }

function opsPct(v) { return v === null || v === undefined ? '—' : (v * 100).toFixed(2) + '%'; }

async function opsRefresh() {
      if (!opsDeckVisible()) return;
      try {
        const res = await fetch('/api/ops/summary');
        const s = await res.json();
        if (s.error) return;

        // rolling
        const r = s.rolling || {};
        const badge = document.getElementById('rolling-badge');
        const dot = document.getElementById('tab-autopilot-dot');
        const running = !!r.running;
        badge.textContent = r.stopping ? 'STOPPING' : (running ? 'CAPTURING' : 'STOPPED');
        badge.className = 'shrink-0 text-[10px] px-2 py-1 rounded border font-bold tracking-wider '
          + (running ? 'border-matrixGreen/60 text-matrixGreen bg-matrixGreen/10'
                     : 'border-slate-600 text-textMuted');
        if (dot) dot.className = 'w-2 h-2 rounded-full ' + (running ? 'bg-matrixGreen animate-pulse' : 'bg-slate-500');
        document.getElementById('btn-rolling-start').disabled = running;
        document.getElementById('btn-rolling-stop').disabled = !running;
        if (r.last_capture_file) {
          document.getElementById('rolling-detail').textContent =
            `last chunk: ${r.last_capture_file.split('/').pop()} — ${r.last_capture_packets} packets`;
        }

        // coverage
        const cov = s.coverage || { rows: [] };
        document.getElementById('coverage-summary').textContent =
          `${cov.contexts_covered}/${cov.contexts_total} contexts · ${cov.total_hours}h total`;
        const body = document.getElementById('coverage-rows');
        body.innerHTML = '';
        for (const row of cov.rows) {
          const tr = document.createElement('tr');
          tr.className = 'border-b border-panelBorder/30';
          tr.innerHTML = `
            <td class="py-1.5 pr-2 text-slate-300">${row.tag}
              <span class="text-textMuted">— ${row.label}</span></td>
            <td class="py-1.5 px-2 text-right text-slate-400">${row.chunks}</td>
            <td class="py-1.5 px-2 text-right ${row.covered ? 'text-matrixGreen' : 'text-textMuted'}">${row.hours.toFixed(2)}</td>
            <td class="py-1.5 px-2 text-right text-slate-400">${row.packets.toLocaleString()}</td>
            <td class="py-1.5 pl-2 ${row.covered ? 'text-matrixGreen' : 'text-amber-400/80'}">${row.covered ? 'covered' : 'thin'}</td>`;
          body.appendChild(tr);
        }
        const nudge = document.getElementById('coverage-nudge');
        if (cov.next_suggestion) {
          nudge.classList.remove('hidden');
          nudge.textContent =
            `Next context worth capturing: "${cov.next_suggestion}". `
            + `While the benign baseline is almost all ports 443/53/80, the champion's decision `
            + `collapses onto two features — more generations cannot fix that, only more varied traffic can.`;
        } else {
          nudge.classList.add('hidden');
        }

        // schedule
        const sch = s.schedule || {};
        const sbadge = document.getElementById('schedule-badge');
        const sbtn = document.getElementById('btn-schedule-install');
        if (!sch.supported) {
          sbadge.textContent = 'N/A';
          sbadge.className = 'shrink-0 text-[10px] px-2 py-1 rounded border border-slate-600 text-textMuted font-bold tracking-wider';
          sbtn.disabled = true;
          document.getElementById('schedule-detail').textContent = sch.note || '';
        } else {
          const all = !!sch.all_installed;
          sbadge.textContent = all ? 'INSTALLED' : 'NOT INSTALLED';
          sbadge.className = 'shrink-0 text-[10px] px-2 py-1 rounded border font-bold tracking-wider '
            + (all ? 'border-matrixGreen/60 text-matrixGreen bg-matrixGreen/10'
                   : 'border-amber-500/60 text-amber-400 bg-amber-500/10');
          if (!opsActiveJob) sbtn.disabled = false;
          document.getElementById('schedule-detail').textContent =
            (sch.tasks || []).map(t => `${t.task}: ${t.installed ? 'ok' : 'missing'} (${t.when})`).join(' · ');
        }

        // installed state
        const t = s.tiers || {}, tr2 = s.training || {}, au = s.audit || {}, ar = s.archive || {};
        const verdictColour = au.verdict === 'PASS' ? 'text-matrixGreen'
                            : au.verdict === 'WARN' ? 'text-amber-400'
                            : au.verdict ? 'text-crimson' : 'text-textMuted';
        document.getElementById('ops-state').innerHTML = `
          <div class="flex justify-between gap-3"><dt class="text-textMuted">champion</dt>
            <dd class="text-slate-300">${s.champion_sha256 || '—'}</dd></div>
          <div class="flex justify-between gap-3"><dt class="text-textMuted">block tier</dt>
            <dd class="text-slate-300">${t.k ?? '—'} flags / ${t.window_sec ?? '—'}s</dd></div>
          <div class="flex justify-between gap-3"><dt class="text-textMuted">high-volume caught</dt>
            <dd class="text-slate-300">${t.caught_pct ?? '—'}%</dd></div>
          <div class="flex justify-between gap-3"><dt class="text-textMuted">holdout TPR / FPR</dt>
            <dd class="text-slate-300">${opsPct(tr2.holdout_tpr)} / ${opsPct(tr2.holdout_fpr)}</dd></div>
          <div class="flex justify-between gap-3"><dt class="text-textMuted">last audit</dt>
            <dd class="${verdictColour} font-bold">${au.verdict || 'never'}</dd></div>
          <div class="flex justify-between gap-3"><dt class="text-textMuted">hours reviewed</dt>
            <dd class="text-slate-300">${au.hours_reviewed ?? '—'}</dd></div>
          <div class="flex justify-between gap-3"><dt class="text-textMuted">archive</dt>
            <dd class="text-slate-300">${(ar.total_artifacts ?? 0)} artifacts</dd></div>`;
      } catch (e) { /* transient */ }
    }

function opsStartPolling() {
      if (opsPollTimer) clearInterval(opsPollTimer);
      opsPollTimer = setInterval(() => { if (opsDeckVisible()) opsRefresh(); }, 5000);
    }

    document.addEventListener('visibilitychange', () => {
      if (opsDeckVisible()) opsRefresh();
    });

    opsLoadTags();
    opsStartPolling();

    // Central delegated action listener (CSP script-src 'self': no
    // inline handlers exist in the markup; buttons carry data-action
    // attributes and read their argument from data-arg / data-ip).
    const ACTIONS = {
        toggledefensemode: (el) => toggleDefenseMode(el.dataset.arg),
        togglelivecapture: (el) => toggleLiveCapture(el.dataset.arg),
        toggleaudio: (el) => toggleAudio(el.dataset.arg),
        triggersimulatedattack: (el) => triggerSimulatedAttack(el.dataset.arg),
        switchdeck: (el) => switchDeck(el.dataset.arg),
        runadversarystresstest: (el) => runAdversaryStressTest(el.dataset.arg),
        triggerevolutionburst: (el) => triggerEvolutionBurst(el.dataset.arg),
        triggerdirectedsurgery: (el) => triggerDirectedSurgery(el.dataset.arg),
        togglecontinuousloop: (el) => toggleContinuousLoop(el.dataset.arg),
        injectcontinuousbatch: (el) => injectContinuousBatch(el.dataset.arg),
        clearcontinuousauditconsole: (el) => clearContinuousAuditConsole(el.dataset.arg),
        opsrollingstart: (el) => opsRollingStart(el.dataset.arg),
        opsrollingstop: (el) => opsRollingStop(el.dataset.arg),
        opsjob: (el) => opsJob(el.dataset.arg),
        opsinstallschedule: (el) => opsInstallSchedule(el.dataset.arg),
        'unban ip': (el) => { const ip = el.dataset.ip; if (ip) unbanIp(ip); },
    };
    document.addEventListener('click', (ev) => {
      const el = ev.target.closest('[data-action]');
      if (!el) return;
      const fn = ACTIONS[el.dataset.action];
      if (typeof fn === 'function') fn(el);
    });
