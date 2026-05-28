/**
 * ═══════════════════════════════════════════════════════════
 *  WireDown — SecurityAIAgent  v2.0
 *  Autonomous threat-response AI with real threat scoring.
 *  No more random flagging — decisions based on backend
 *  threat engine signals (ARP spoof, KRACK, XZ backdoor, etc.)
 * ═══════════════════════════════════════════════════════════
 */

class SecurityAIAgent {
  /**
   * @param {Matter.Engine}  engine
   * @param {Matter.Body}    blackHole
   * @param {object}         socket      - Socket.IO client
   * @param {object}         options
   */
  constructor(engine, blackHole, socket, options = {}) {
    this.engine    = engine;
    this.blackHole = blackHole;
    this.socket    = socket;

    this.opts = {
      attractionStrength: options.attractionStrength ?? 0.00035,
      minForce:           options.minForce ?? 0.00003,
      maxForce:           options.maxForce ?? 0.004,
      captureRadius:      options.captureRadius ?? 60,
      attackerDamping:    options.attackerDamping ?? 0.98,
      driftStrength:      options.driftStrength ?? 0.00004,
      stalkFrames:        options.stalkFrames ?? 90,
      trailLength:        options.trailLength ?? 20,

      /** Threat score thresholds */
      suspiciousThreshold: options.suspiciousThreshold ?? 30,
      attackerThreshold:   options.attackerThreshold ?? 60,
    };

    /** @type {Map<number, DeviceMeta>} body.id → metadata */
    this.deviceMap = new Map();

    /** @type {Map<string, number>} mac → body.id for quick lookup */
    this.macIndex = new Map();

    /** Bodies being consumed (destroy animation) */
    this.destroying = new Map();

    /** Attack type icons for rendering */
    this.attackIcons = {
      xz_backdoor:   "☠",
      krack_attack:  "🔓",
      arp_spoof:     "🕸",
      deauth_flood:  "⚡",
      port_scan:     "🔍",
      brute_force:   "🔑",
      mac_flood:     "🌊",
      dns_tunnel:    "🕳",
      ssh_login:     "💻",
      admin_login:   "🚪",
    };

    /** Event log callback */
    this.onEvent = options.onEvent || (() => {});

    this._frameCount = 0;

    this._bindEngineEvents();
  }

  /* ══════════════════════════════════════════════════════════
   *  PUBLIC API
   * ══════════════════════════════════════════════════════════ */

  /**
   * Register a new device. Starts as safe — threat score determines status.
   */
  registerDevice(body, mac, extra = {}) {
    const meta = {
      body,
      mac,
      isAttacker:    false,
      isSuspicious:  false,
      threatScore:   extra.threatScore ?? 0,
      threatStatus:  "safe",
      attackTypes:   [],
      throttleStage: null,
      throttleProgress: 0,
      status:        "active",       // active | suspicious | stalking | engaging | captured | destroyed
      framesSeen:    0,
      trail:         [],
      rssi:          extra.rssi ?? -50,
      channel:       extra.channel ?? 6,
      spawnTime:     performance.now(),
    };

    this.deviceMap.set(body.id, meta);
    this.macIndex.set(mac, body.id);

    this.onEvent("info", `Device ${mac} registered — monitoring (score: ${meta.threatScore})`);
    this._evaluateThreatLevel(meta);

    return meta;
  }

  /**
   * Update a device's threat score from the backend.
   */
  updateThreatScore(mac, score, signals = []) {
    const bodyId = this.macIndex.get(mac);
    if (!bodyId) return null;
    const meta = this.deviceMap.get(bodyId);
    if (!meta) return null;

    const oldScore = meta.threatScore;
    meta.threatScore = score;

    for (const sig of signals) {
      if (!meta.attackTypes.includes(sig)) {
        meta.attackTypes.push(sig);
      }
    }

    if (score !== oldScore) {
      this._evaluateThreatLevel(meta);
    }

    return meta;
  }

  /**
   * Record an attack detection event for a device.
   */
  recordAttack(mac, attackType, details = {}) {
    const bodyId = this.macIndex.get(mac);
    if (!bodyId) return null;
    const meta = this.deviceMap.get(bodyId);
    if (!meta) return null;

    if (!meta.attackTypes.includes(attackType)) {
      meta.attackTypes.push(attackType);
    }

    this.onEvent("critical", `Attack detected on ${mac}: ${attackType}`);
    return meta;
  }

  /**
   * Update throttle status for a device.
   */
  updateThrottle(mac, stage, progress) {
    const bodyId = this.macIndex.get(mac);
    if (!bodyId) return;
    const meta = this.deviceMap.get(bodyId);
    if (!meta) return;

    meta.throttleStage = stage;
    meta.throttleProgress = progress;
  }

  /**
   * Manually flag a device as an attacker (force override).
   */
  flagAsAttacker(bodyId) {
    const meta = this.deviceMap.get(bodyId);
    if (!meta || meta.isAttacker) return;
    meta.threatScore = Math.max(meta.threatScore, this.opts.attackerThreshold);
    this._evaluateThreatLevel(meta);
    this.onEvent("critical", `Device ${meta.mac} manually flagged — threat score set to ${meta.threatScore}`);
  }

  /**
   * Flag by MAC address.
   */
  flagAsAttackerByMac(mac) {
    const bodyId = this.macIndex.get(mac);
    if (bodyId) this.flagAsAttacker(bodyId);
  }

  getMeta(bodyId) {
    return this.deviceMap.get(bodyId);
  }

  getMetaByMac(mac) {
    const bodyId = this.macIndex.get(mac);
    return bodyId ? this.deviceMap.get(bodyId) : undefined;
  }

  getAllDevices() {
    return Array.from(this.deviceMap.values());
  }

  /* ══════════════════════════════════════════════════════════
   *  THREAT EVALUATION
   * ══════════════════════════════════════════════════════════ */

  _evaluateThreatLevel(meta) {
    const score = meta.threatScore;
    const wasAttacker = meta.isAttacker;
    const wasSuspicious = meta.isSuspicious;

    if (score >= this.opts.attackerThreshold) {
      meta.threatStatus = "attacker";
      meta.isAttacker = true;
      meta.isSuspicious = false;

      if (!wasAttacker && meta.status !== "captured" && meta.status !== "destroyed") {
        meta.status = "stalking";
        meta.framesSeen = 0;
        this.onEvent("critical",
          `⚠ THREAT CONFIRMED: ${meta.mac} — score ${score} — ${meta.attackTypes.join(", ") || "behavioral"}`
        );
      }
    } else if (score >= this.opts.suspiciousThreshold) {
      meta.threatStatus = "suspicious";
      meta.isSuspicious = true;
      meta.isAttacker = false;

      if (!wasSuspicious) {
        meta.status = "suspicious";
        this.onEvent("warning",
          `Device ${meta.mac} flagged as suspicious — score ${score}`
        );
      }
    } else {
      meta.threatStatus = "safe";
      meta.isAttacker = false;
      meta.isSuspicious = false;
    }
  }

  /* ══════════════════════════════════════════════════════════
   *  ENGINE EVENTS
   * ══════════════════════════════════════════════════════════ */

  _bindEngineEvents() {
    const Matter = window.Matter;

    Matter.Events.on(this.engine, "beforeUpdate", () => {
      this._frameCount++;
      this._tickAI();
    });

    Matter.Events.on(this.engine, "collisionStart", (event) => {
      for (const pair of event.pairs) {
        this._handleCollision(pair.bodyA, pair.bodyB);
        this._handleCollision(pair.bodyB, pair.bodyA);
      }
    });
  }

  /* ══════════════════════════════════════════════════════════
   *  CORE AI TICK
   * ══════════════════════════════════════════════════════════ */

  _tickAI() {
    const Matter = window.Matter;
    const bhPos  = this.blackHole.position;

    for (const [id, meta] of this.deviceMap) {
      if (meta.status === "destroyed" || meta.status === "captured") continue;

      const body = meta.body;
      const pos  = body.position;

      meta.trail.push({ x: pos.x, y: pos.y });
      if (meta.trail.length > this.opts.trailLength) meta.trail.shift();

      meta.framesSeen++;

      if (meta.isAttacker) {
        this._processAttacker(meta, bhPos, Matter);
      } else if (meta.isSuspicious) {
        this._processSuspicious(meta, Matter);
      } else {
        this._processSafe(meta, Matter);
      }
    }

    this._processDestroyAnimations(Matter);
  }

  _processAttacker(meta, bhPos, Matter) {
    const body = meta.body;
    const pos  = body.position;

    /* Phase 1: Stalk */
    if (meta.status === "stalking") {
      if (meta.framesSeen >= this.opts.stalkFrames) {
        meta.status = "engaging";
        this.onEvent("critical", `AI engaging ${meta.mac} — dragging to Black Hole`);
      }
      const wobble = 0.00002;
      Matter.Body.applyForce(body, pos, {
        x: (Math.random() - 0.5) * wobble,
        y: (Math.random() - 0.5) * wobble,
      });
      return;
    }

    /* Phase 2: Engage — inverse-square attraction */
    const dx   = bhPos.x - pos.x;
    const dy   = bhPos.y - pos.y;
    const dist = Math.sqrt(dx * dx + dy * dy);

    if (dist < 1) return;

    let forceMag = this.opts.attractionStrength / Math.max(dist * 0.01, 0.5);

    /* Higher threat scores = stronger pull */
    const scoreMult = Math.min(meta.threatScore / 60, 2.5);
    forceMag *= scoreMult;

    forceMag = Math.max(this.opts.minForce, Math.min(this.opts.maxForce, forceMag));

    const nx = dx / dist;
    const ny = dy / dist;

    Matter.Body.applyForce(body, pos, { x: nx * forceMag, y: ny * forceMag });

    Matter.Body.setVelocity(body, {
      x: body.velocity.x * this.opts.attackerDamping,
      y: body.velocity.y * this.opts.attackerDamping,
    });

    if (dist < 200) {
      Matter.Body.scale(body, 0.998, 0.998);
    }
  }

  _processSuspicious(meta, Matter) {
    const body = meta.body;
    const pos  = body.position;

    /* Slightly agitated drift — not engaged yet but noticeably unsettled */
    const drift = this.opts.driftStrength * 2;
    Matter.Body.applyForce(body, pos, {
      x: (Math.random() - 0.5) * drift,
      y: (Math.random() - 0.5) * drift,
    });

    this._keepOnScreen(body, pos, Matter);
  }

  _processSafe(meta, Matter) {
    const body = meta.body;
    const pos  = body.position;

    const drift = this.opts.driftStrength;
    Matter.Body.applyForce(body, pos, {
      x: (Math.random() - 0.5) * drift,
      y: (Math.random() - 0.5) * drift,
    });

    this._keepOnScreen(body, pos, Matter);
  }

  _keepOnScreen(body, pos, Matter) {
    const canvas = this.engine.render?.canvas;
    if (!canvas) return;
    const margin = 80;
    const w = canvas.width;
    const h = canvas.height;
    const bounce = 0.0002;

    if (pos.x < margin)     Matter.Body.applyForce(body, pos, { x:  bounce, y: 0 });
    if (pos.x > w - margin) Matter.Body.applyForce(body, pos, { x: -bounce, y: 0 });
    if (pos.y < margin)     Matter.Body.applyForce(body, pos, { x: 0, y:  bounce });
    if (pos.y > h - margin) Matter.Body.applyForce(body, pos, { x: 0, y: -bounce });
  }

  /* ── Collision ────────────────────────────────────────────── */

  _handleCollision(bodyA, bodyB) {
    if (bodyB.id !== this.blackHole.id) return;

    const meta = this.deviceMap.get(bodyA.id);
    if (!meta || !meta.isAttacker) return;
    if (meta.status === "captured" || meta.status === "destroyed") return;

    meta.status = "captured";
    this.onEvent("success",
      `${meta.mac} captured by Black Hole [score: ${meta.threatScore}, attacks: ${meta.attackTypes.join(", ")}]`
    );

    this.destroying.set(bodyA.id, {
      body: bodyA,
      meta,
      frame: 0,
      totalFrames: 30,
    });

    if (this.socket && this.socket.connected) {
      this.socket.emit("execute_isolation", {
        mac:    meta.mac,
        reason: `AI Agent: threat score ${meta.threatScore} — ${meta.attackTypes.join(", ")}`,
      });
      this.onEvent("critical", `Isolation command sent for ${meta.mac}`);
    }
  }

  /* ── Destroy Animation ────────────────────────────────────── */

  _processDestroyAnimations(Matter) {
    for (const [id, anim] of this.destroying) {
      anim.frame++;
      const progress = anim.frame / anim.totalFrames;

      const scale = 1 - progress * 0.04;
      if (scale > 0.1) {
        Matter.Body.scale(anim.body, scale, scale);
      }
      Matter.Body.setAngularVelocity(anim.body, anim.body.angularVelocity + 0.05);

      if (anim.frame >= anim.totalFrames) {
        Matter.Composite.remove(this.engine.world, anim.body);
        anim.meta.status = "destroyed";
        this.destroying.delete(id);
        this.onEvent("success", `${anim.meta.mac} destroyed — removed from network`);
      }
    }
  }

  /* ══════════════════════════════════════════════════════════
   *  CUSTOM RENDERER
   * ══════════════════════════════════════════════════════════ */

  drawOverlays(ctx) {
    const bhPos = this.blackHole.position;

    for (const [id, meta] of this.deviceMap) {
      if (meta.status === "destroyed") continue;

      const body = meta.body;
      const pos  = body.position;

      /* ── Trail ── */
      if ((meta.isAttacker || meta.isSuspicious) && meta.trail.length > 2) {
        ctx.beginPath();
        ctx.moveTo(meta.trail[0].x, meta.trail[0].y);
        for (let i = 1; i < meta.trail.length; i++) {
          ctx.lineTo(meta.trail[i].x, meta.trail[i].y);
        }
        ctx.strokeStyle = meta.isAttacker
          ? `rgba(255, 23, 68, ${meta.status === "engaging" ? 0.5 : 0.2})`
          : "rgba(255, 171, 0, 0.15)";
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      /* ── Engagement beam ── */
      if (meta.status === "engaging") {
        const gradient = ctx.createLinearGradient(pos.x, pos.y, bhPos.x, bhPos.y);
        gradient.addColorStop(0, "rgba(255, 23, 68, 0.6)");
        gradient.addColorStop(1, "rgba(224, 64, 251, 0.1)");

        ctx.beginPath();
        ctx.moveTo(pos.x, pos.y);
        ctx.lineTo(bhPos.x, bhPos.y);
        ctx.strokeStyle = gradient;
        ctx.lineWidth = 1;
        ctx.setLineDash([4, 8]);
        ctx.stroke();
        ctx.setLineDash([]);

        const pulseRadius = body.circleRadius + 8 + Math.sin(this._frameCount * 0.1) * 4;
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, pulseRadius, 0, Math.PI * 2);
        ctx.strokeStyle = "rgba(255, 23, 68, 0.4)";
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      /* ── Stalking indicator ── */
      if (meta.status === "stalking") {
        const flashAlpha = 0.3 + 0.2 * Math.sin(this._frameCount * 0.15);
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, body.circleRadius + 12, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(255, 171, 0, ${flashAlpha})`;
        ctx.lineWidth = 1;
        ctx.setLineDash([3, 5]);
        ctx.stroke();
        ctx.setLineDash([]);
      }

      /* ── Suspicious indicator (amber glow ring) ── */
      if (meta.status === "suspicious") {
        const pulseAlpha = 0.15 + 0.1 * Math.sin(this._frameCount * 0.08);
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, body.circleRadius + 10, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(255, 171, 0, ${pulseAlpha})`;
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      /* ── Threat score ring (color-coded arc) ── */
      if (meta.threatScore > 0 && meta.status !== "captured") {
        const scoreNorm = Math.min(meta.threatScore / 100, 1);
        const arcEnd = scoreNorm * Math.PI * 2;
        const ringRadius = body.circleRadius + 5;

        let ringColor;
        if (meta.threatScore >= this.opts.attackerThreshold) {
          ringColor = `rgba(255, 23, 68, 0.7)`;
        } else if (meta.threatScore >= this.opts.suspiciousThreshold) {
          ringColor = `rgba(255, 171, 0, 0.6)`;
        } else {
          ringColor = `rgba(0, 229, 255, 0.3)`;
        }

        ctx.beginPath();
        ctx.arc(pos.x, pos.y, ringRadius, -Math.PI / 2, -Math.PI / 2 + arcEnd);
        ctx.strokeStyle = ringColor;
        ctx.lineWidth = 2.5;
        ctx.stroke();
      }

      /* ── Throttle progress ring ── */
      if (meta.throttleStage && meta.throttleStage !== "FULL") {
        const throttleRadius = body.circleRadius + 18;
        const throttleArc = (meta.throttleProgress / 100) * Math.PI * 2;

        ctx.beginPath();
        ctx.arc(pos.x, pos.y, throttleRadius, -Math.PI / 2, -Math.PI / 2 + throttleArc);
        ctx.strokeStyle = "rgba(224, 64, 251, 0.5)";
        ctx.lineWidth = 2;
        ctx.setLineDash([2, 3]);
        ctx.stroke();
        ctx.setLineDash([]);

        ctx.font = "8px 'JetBrains Mono', monospace";
        ctx.textAlign = "center";
        ctx.fillStyle = "rgba(224, 64, 251, 0.6)";
        ctx.fillText(`⏬ ${meta.throttleStage}`, pos.x, pos.y - body.circleRadius - 20);
      }

      /* ── Attack type icons ── */
      if (meta.attackTypes.length > 0 && meta.status !== "captured") {
        const icons = meta.attackTypes
          .map(t => this.attackIcons[t] || "⚠")
          .slice(0, 3)
          .join(" ");

        ctx.font = "11px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText(icons, pos.x, pos.y - body.circleRadius - 8);
      }

      /* ── MAC + score label ── */
      if (meta.status !== "captured") {
        ctx.font = "10px 'JetBrains Mono', monospace";
        ctx.textAlign = "center";

        if (meta.isAttacker) {
          ctx.fillStyle = "rgba(255, 23, 68, 0.8)";
        } else if (meta.isSuspicious) {
          ctx.fillStyle = "rgba(255, 171, 0, 0.7)";
        } else {
          ctx.fillStyle = "rgba(0, 229, 255, 0.5)";
        }
        ctx.fillText(meta.mac, pos.x, pos.y + body.circleRadius + 14);

        /* Score label */
        if (meta.threatScore > 0) {
          const scoreColor = meta.threatScore >= 60
            ? "rgba(255, 23, 68, 0.7)"
            : meta.threatScore >= 30
              ? "rgba(255, 171, 0, 0.6)"
              : "rgba(0, 229, 255, 0.4)";
          ctx.fillStyle = scoreColor;
          ctx.fillText(`Score: ${meta.threatScore}`, pos.x, pos.y + body.circleRadius + 26);
        }

        /* Threat label */
        if (meta.isAttacker && meta.status !== "stalking") {
          ctx.fillStyle = "rgba(255, 23, 68, 0.6)";
          const label = meta.attackTypes[0]
            ? `⚠ ${meta.attackTypes[0].toUpperCase().replace("_", " ")}`
            : "⚠ THREAT";
          ctx.fillText(label, pos.x, pos.y + body.circleRadius + 38);
        }
      }
    }

    /* ── Black Hole label ── */
    ctx.font = "bold 11px 'Orbitron', sans-serif";
    ctx.textAlign = "center";
    ctx.fillStyle = "rgba(224, 64, 251, 0.6)";
    ctx.fillText("BLACK HOLE", bhPos.x, bhPos.y + this.blackHole.circleRadius + 20);
    ctx.font = "9px 'JetBrains Mono', monospace";
    ctx.fillStyle = "rgba(224, 64, 251, 0.35)";
    ctx.fillText("[ NETWORK TRAP ]", bhPos.x, bhPos.y + this.blackHole.circleRadius + 34);
  }
}

window.SecurityAIAgent = SecurityAIAgent;
