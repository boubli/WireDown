/**
 * ═══════════════════════════════════════════════════════════
 *  WireDown — Physics World
 *  Matter.js zero-gravity engine, Black Hole, device spawning,
 *  Socket.IO bridge, and custom renderer.
 * ═══════════════════════════════════════════════════════════
 */

(function () {
  "use strict";

  const {
    Engine,
    Render,
    Runner,
    World,
    Bodies,
    Body,
    Composite,
    Events,
    Mouse,
    MouseConstraint,
    Vector,
  } = Matter;

  /* ── Configuration ──────────────────────────────────────── */
  // Dynamically connect to the backend running on the same IP as the frontend
  const BACKEND_URL    = `http://${window.location.hostname}:5000`;
  const WS_NAMESPACE   = "/ws/frontend";
  const BH_RADIUS      = 55;
  const DEVICE_RADIUS  = 16;
  const SPAWN_MARGIN   = 120;
  const WALL_THICKNESS = 60;

  /* ── Canvas sizing ──────────────────────────────────────── */
  const container = document.getElementById("physics-canvas");
  const W = window.innerWidth;
  const H = window.innerHeight;

  /* ── Engine (zero gravity) ──────────────────────────────── */
  const engine = Engine.create({
    gravity: { x: 0, y: 0, scale: 0 },
  });

  /* ── Renderer ───────────────────────────────────────────── */
  const render = Render.create({
    element: container,
    engine:  engine,
    options: {
      width:            W,
      height:           H,
      pixelRatio:       window.devicePixelRatio || 1,
      background:       "#06070d",
      wireframes:       false,
      showAngleIndicator: false,
      showCollisions:   false,
      showVelocity:     false,
    },
  });
  Render.run(render);

  /* Store render reference on engine for AI agent boundary checks */
  engine.render = render;

  /* ── Runner ─────────────────────────────────────────────── */
  const runner = Runner.create();
  Runner.run(runner, engine);

  /* ── Invisible walls to keep bodies on-screen ───────────── */
  const wallOpts = {
    isStatic: true,
    render: { visible: false },
    restitution: 0.5,
    friction: 0,
    label: "wall",
  };
  Composite.add(engine.world, [
    Bodies.rectangle(W / 2, -WALL_THICKNESS / 2,          W + 200, WALL_THICKNESS, wallOpts),
    Bodies.rectangle(W / 2, H + WALL_THICKNESS / 2,       W + 200, WALL_THICKNESS, wallOpts),
    Bodies.rectangle(-WALL_THICKNESS / 2, H / 2,          WALL_THICKNESS, H + 200, wallOpts),
    Bodies.rectangle(W + WALL_THICKNESS / 2, H / 2,       WALL_THICKNESS, H + 200, wallOpts),
  ]);

  /* ── Black Hole (central static attractor) ──────────────── */
  const blackHole = Bodies.circle(W / 2, H / 2, BH_RADIUS, {
    isStatic:    true,
    isSensor:    true,         // detect collisions without physical bounce
    label:       "BlackHole",
    render: {
      fillStyle:   "#0d001a",
      strokeStyle: "#e040fb",
      lineWidth:   2,
    },
  });
  Composite.add(engine.world, blackHole);

  /* ── Mouse interaction (drag safe bodies around) ────────── */
  const mouse = Mouse.create(render.canvas);
  const mouseConstraint = MouseConstraint.create(engine, {
    mouse,
    constraint: {
      stiffness: 0.1,
      render: { visible: false },
    },
  });
  Composite.add(engine.world, mouseConstraint);
  render.mouse = mouse;

  /* ── Socket.IO ──────────────────────────────────────────── */
  let socket;
  try {
    socket = io(BACKEND_URL + WS_NAMESPACE, {
      transports: ["websocket", "polling"],
      reconnection: true,
      reconnectionDelay: 2000,
    });
  } catch (e) {
    console.warn("[WireDown] Socket.IO connection failed — running in offline mode.", e);
    socket = {
      connected: false,
      on: () => {},
      emit: () => {},
    };
  }

  /* ── AI Agent ───────────────────────────────────────────── */
  const aiAgent = new SecurityAIAgent(engine, blackHole, socket, {
    attractionStrength: 0.00035,
    attackerProbability: 0.2,
    stalkFrames: 90,
    onEvent: addEventLog,
  });

  /* ── Device Tracking ────────────────────────────────────── */
  const macToBodyId = new Map();

  function generateColor(isAttacker) {
    if (isAttacker) {
      return {
        fillStyle:   "rgba(255, 23, 68, 0.7)",
        strokeStyle: "#ff1744",
        lineWidth:   2,
      };
    }
    const hue = 170 + Math.random() * 60; // cyan-blue range
    return {
      fillStyle:   `hsla(${hue}, 80%, 55%, 0.6)`,
      strokeStyle: `hsla(${hue}, 90%, 65%, 0.9)`,
      lineWidth:   1.5,
    };
  }

  function spawnDevice(mac, rssi, channel, forceAttacker) {
    if (macToBodyId.has(mac)) return; // already in the world

    /* Random spawn position along the edges */
    let x, y;
    const edge = Math.floor(Math.random() * 4);
    switch (edge) {
      case 0: x = SPAWN_MARGIN + Math.random() * (W - 2 * SPAWN_MARGIN); y = SPAWN_MARGIN; break;
      case 1: x = SPAWN_MARGIN + Math.random() * (W - 2 * SPAWN_MARGIN); y = H - SPAWN_MARGIN; break;
      case 2: x = SPAWN_MARGIN; y = SPAWN_MARGIN + Math.random() * (H - 2 * SPAWN_MARGIN); break;
      case 3: x = W - SPAWN_MARGIN; y = SPAWN_MARGIN + Math.random() * (H - 2 * SPAWN_MARGIN); break;
    }

    /* Will the AI flag this one? We peek ahead so we can color it correctly.
       We'll pass forceAttacker to the AI by temporarily overriding probability. */
    let tempProb = aiAgent.opts.attackerProbability;
    if (forceAttacker === true)  aiAgent.opts.attackerProbability = 1;
    if (forceAttacker === false) aiAgent.opts.attackerProbability = 0;

    /* Speculatively check — we need the color before creating the body,
       but the AI decides randomly. We'll create, register, then re-color. */
    const body = Bodies.circle(x, y, DEVICE_RADIUS, {
      restitution: 0.8,
      friction:    0,
      frictionAir: 0.01,
      density:     0.002,
      label:       "device:" + mac,
      render:      generateColor(false), // placeholder
    });

    /* Give it a gentle initial velocity */
    Body.setVelocity(body, {
      x: (Math.random() - 0.5) * 2,
      y: (Math.random() - 0.5) * 2,
    });

    Composite.add(engine.world, body);
    macToBodyId.set(mac, body.id);

    /* Register with AI — this decides attacker status */
    const meta = aiAgent.registerDevice(body, mac, { rssi, channel });

    /* Restore probability */
    aiAgent.opts.attackerProbability = tempProb;

    /* Now re-color based on AI decision */
    body.render = {
      ...body.render,
      ...generateColor(meta.isAttacker),
    };

    /* Update HUD */
    addDeviceToList(meta);
    updateStats();
  }

  /* ── Socket.IO Event Handlers ───────────────────────────── */

  socket.on("connect", () => {
    console.log("[WireDown] Connected to backend");
  });

  socket.on("disconnect", () => {
    console.warn("[WireDown] Disconnected from backend");
  });

  socket.on("init", (data) => {
    console.log("[WireDown] Init data received:", data);
    if (data.devices) {
      for (const dev of data.devices) {
        if (dev.status !== "destroyed") {
          spawnDevice(dev.mac, dev.rssi, dev.channel);
        }
      }
    }
  });

  socket.on("new_device", (dev) => {
    spawnDevice(dev.mac, dev.rssi, dev.channel);
  });



  socket.on("isolation_confirmed", (data) => {
    addEventLog("success", `Isolation confirmed for ${data.mac}`);
    updateStats();
  });

  socket.on("device_flagged", (dev) => {
    const bodyId = macToBodyId.get(dev.mac);
    if (bodyId) {
      aiAgent.flagAsAttacker(bodyId);
      const body = Composite.allBodies(engine.world).find((b) => b.id === bodyId);
      if (body) {
        body.render = { ...body.render, ...generateColor(true) };
      }
    }
    updateDeviceList();
  });

  /* ── HUD Functions ──────────────────────────────────────── */



  function updateStats() {
    const all       = aiAgent.getAllDevices();
    const threats   = all.filter((d) => d.isAttacker && d.status !== "destroyed");
    const isolated  = all.filter((d) => d.status === "destroyed" || d.status === "captured");
    const safe      = all.filter((d) => !d.isAttacker && d.status === "active");

    document.getElementById("statDevices").textContent  = all.length;
    document.getElementById("statThreats").textContent  = threats.length;
    document.getElementById("statIsolated").textContent = isolated.length;
    document.getElementById("statSafe").textContent     = safe.length;
  }

  const deviceListEl = document.getElementById("deviceList");
  let deviceListInitialized = false;

  function addDeviceToList(meta) {
    if (!deviceListInitialized) {
      deviceListEl.innerHTML = "";
      deviceListInitialized = true;
    }

    const entry = document.createElement("div");
    entry.className = "device-entry" + (meta.isAttacker ? " attacker" : "");
    entry.id = "dev-" + meta.mac.replace(/:/g, "");
    entry.innerHTML = `
      <span class="device-indicator ${meta.isAttacker ? "threat" : "safe"}"></span>
      <span class="device-mac">${meta.mac}</span>
      <span class="device-rssi">${meta.rssi} dBm</span>
    `;
    deviceListEl.prepend(entry);
  }

  function updateDeviceList() {
    const all = aiAgent.getAllDevices();
    for (const meta of all) {
      const el = document.getElementById("dev-" + meta.mac.replace(/:/g, ""));
      if (!el) continue;

      el.className = "device-entry";
      if (meta.status === "destroyed" || meta.status === "captured") {
        el.className += " isolated";
        const indicator = el.querySelector(".device-indicator");
        if (indicator) indicator.className = "device-indicator dead";
      } else if (meta.isAttacker) {
        el.className += " attacker";
        const indicator = el.querySelector(".device-indicator");
        if (indicator) indicator.className = "device-indicator threat";
      }
    }
  }

  const eventLogEl = document.getElementById("eventLog");
  const MAX_LOG_ENTRIES = 50;

  function addEventLog(level, message) {
    const entry = document.createElement("div");
    entry.className = "event-entry " + level;
    const time = new Date().toLocaleTimeString("en-US", { hour12: false });
    entry.textContent = `[${time}] ${message}`;
    eventLogEl.appendChild(entry);

    while (eventLogEl.children.length > MAX_LOG_ENTRIES) {
      eventLogEl.removeChild(eventLogEl.firstChild);
    }
    eventLogEl.scrollTop = eventLogEl.scrollHeight;
  }

  /* ── Live Clock ─────────────────────────────────────────── */
  function updateClock() {
    document.getElementById("liveClock").textContent =
      new Date().toLocaleTimeString("en-US", { hour12: false });
  }
  setInterval(updateClock, 1000);
  updateClock();

  /* ── FPS Counter ────────────────────────────────────────── */
  let fpsFrames = 0;
  let fpsLast   = performance.now();
  const fpsEl   = document.getElementById("fpsCounter");

  function updateFPS() {
    fpsFrames++;
    const now = performance.now();
    if (now - fpsLast >= 1000) {
      fpsEl.textContent = fpsFrames + " FPS";
      fpsFrames = 0;
      fpsLast = now;
    }
  }

  /* ── Custom Render Pass ─────────────────────────────────── */

  Events.on(render, "afterRender", () => {
    const ctx = render.context;
    updateFPS();

    /* ── Black Hole visual effects ── */
    const bh = blackHole.position;
    const time = performance.now() * 0.001;

    /* Pulsating outer glow */
    const glowRadius = BH_RADIUS + 25 + Math.sin(time * 2) * 8;
    const gradient = ctx.createRadialGradient(bh.x, bh.y, BH_RADIUS * 0.5, bh.x, bh.y, glowRadius);
    gradient.addColorStop(0, "rgba(224, 64, 251, 0.15)");
    gradient.addColorStop(0.5, "rgba(224, 64, 251, 0.05)");
    gradient.addColorStop(1, "rgba(224, 64, 251, 0)");

    ctx.beginPath();
    ctx.arc(bh.x, bh.y, glowRadius, 0, Math.PI * 2);
    ctx.fillStyle = gradient;
    ctx.fill();

    /* Rotating accretion rings */
    ctx.save();
    ctx.translate(bh.x, bh.y);
    for (let i = 0; i < 3; i++) {
      const ringRadius = BH_RADIUS + 8 + i * 12;
      const rotation = time * (0.5 + i * 0.3) * (i % 2 === 0 ? 1 : -1);
      ctx.rotate(rotation);
      ctx.beginPath();
      ctx.arc(0, 0, ringRadius, 0, Math.PI * 0.8);
      ctx.strokeStyle = `rgba(224, 64, 251, ${0.25 - i * 0.06})`;
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.rotate(-rotation);
    }
    ctx.restore();

    /* Inner core glow */
    const coreGradient = ctx.createRadialGradient(bh.x, bh.y, 0, bh.x, bh.y, BH_RADIUS * 0.7);
    coreGradient.addColorStop(0, "rgba(224, 64, 251, 0.3)");
    coreGradient.addColorStop(1, "rgba(13, 0, 26, 1)");
    ctx.beginPath();
    ctx.arc(bh.x, bh.y, BH_RADIUS * 0.7, 0, Math.PI * 2);
    ctx.fillStyle = coreGradient;
    ctx.fill();

    /* ── Grid pattern (subtle) ── */
    ctx.strokeStyle = "rgba(0, 229, 255, 0.015)";
    ctx.lineWidth = 0.5;
    const gridSize = 80;
    for (let gx = 0; gx < W; gx += gridSize) {
      ctx.beginPath();
      ctx.moveTo(gx, 0);
      ctx.lineTo(gx, H);
      ctx.stroke();
    }
    for (let gy = 0; gy < H; gy += gridSize) {
      ctx.beginPath();
      ctx.moveTo(0, gy);
      ctx.lineTo(W, gy);
      ctx.stroke();
    }

    /* ── AI overlays ── */
    aiAgent.drawOverlays(ctx);

    /* ── Update device list statuses ── */
    updateDeviceList();
    updateStats();
  });

  /* ── Control Buttons ────────────────────────────────────── */

  let simCounter = 0;

  document.getElementById("btnSimulate").addEventListener("click", () => {
    simCounter++;
    const mac = `SIM:${String(simCounter).padStart(2, "0")}:${randHex()}:${randHex()}:${randHex()}:${randHex()}`;

    if (socket.connected) {
      socket.emit("simulate_device", { mac });
    } else {
      spawnDevice(mac, -50 - Math.floor(Math.random() * 30), 6, false);
    }
  });

  document.getElementById("btnSpawnAttacker").addEventListener("click", () => {
    simCounter++;
    const mac = `ATK:${String(simCounter).padStart(2, "0")}:${randHex()}:${randHex()}:${randHex()}:${randHex()}`;
    spawnDevice(mac, -30 - Math.floor(Math.random() * 20), 6, true);
  });

  function randHex() {
    return Math.floor(Math.random() * 256).toString(16).toUpperCase().padStart(2, "0");
  }

  /* ── Window Resize ──────────────────────────────────────── */

  window.addEventListener("resize", () => {
    render.canvas.width  = window.innerWidth;
    render.canvas.height = window.innerHeight;
    render.options.width  = window.innerWidth;
    render.options.height = window.innerHeight;
    Body.setPosition(blackHole, {
      x: window.innerWidth / 2,
      y: window.innerHeight / 2,
    });
  });

  /* ── Boot log ───────────────────────────────────────────── */
  addEventLog("info", "Matter.js engine started — gravity disabled");
  addEventLog("info", "Black Hole placed at canvas center");
  addEventLog("info", `Connecting to backend at ${BACKEND_URL}...`);

  console.log("[WireDown] Physics world initialized.");
  console.log("[WireDown] Black Hole at", W / 2, H / 2);

})();
