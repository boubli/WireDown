(function() {
  const btnEspSetup = document.getElementById('btnEspSetup');
  const modalOverlay = document.getElementById('espModalOverlay');
  const btnClose = document.getElementById('btnCloseEspModal');
  const btnTogglePw = document.getElementById('btnTogglePw');
  const espPassword = document.getElementById('espPassword');
  const espBackendIp = document.getElementById('espBackendIp');
  
  const detectBadge = document.getElementById('espDetectBadge');
  const detectDot = document.getElementById('espDetectDot');
  const detectLabel = document.getElementById('espDetectLabel');
  
  const btnFlash = document.getElementById('btnFlashEsp');
  const formContainer = document.getElementById('espFormContainer');
  const consoleContainer = document.getElementById('espConsoleContainer');
  const espConsole = document.getElementById('espConsole');
  const btnConsoleClose = document.getElementById('btnConsoleClose');
  
  let statusInterval = null;

  // Open modal
  btnEspSetup.addEventListener('click', () => {
    modalOverlay.classList.add('active');
    espBackendIp.value = window.location.hostname; // Pre-fill backend IP
    checkDevice();
  });

  // Close modal
  btnClose.addEventListener('click', closeModal);
  btnConsoleClose.addEventListener('click', closeModal);
  
  function closeModal() {
    modalOverlay.classList.remove('active');
    if (statusInterval) clearInterval(statusInterval);
    // Reset views
    setTimeout(() => {
      formContainer.style.display = 'block';
      consoleContainer.style.display = 'none';
      espConsole.textContent = '';
    }, 300);
  }

  // Toggle password visibility
  btnTogglePw.addEventListener('click', () => {
    if (espPassword.type === 'password') {
      espPassword.type = 'text';
      btnTogglePw.textContent = '🔒';
    } else {
      espPassword.type = 'password';
      btnTogglePw.textContent = '👁';
    }
  });

  // Ping backend to detect ESP32
  async function checkDevice() {
    detectLabel.textContent = "Checking...";
    detectDot.className = "status-dot suspicious";
    detectBadge.style.borderColor = "var(--accent-amber)";
    btnFlash.disabled = true;
    btnFlash.style.opacity = "0.5";

    try {
      const res = await fetch('/api/esp32/detect');
      const data = await res.json();
      
      if (data.status === 'ok' && data.port) {
        detectLabel.textContent = `USB Detected (${data.port})`;
        detectLabel.style.color = "var(--accent-green)";
        detectDot.className = "status-dot online";
        detectBadge.style.borderColor = "rgba(0,230,118,0.3)";
        btnFlash.disabled = false;
        btnFlash.style.opacity = "1";
      } else {
        setNoDevice();
      }
    } catch (e) {
      setNoDevice();
    }
  }
  
  function setNoDevice() {
    detectLabel.textContent = "No Device Found";
    detectLabel.style.color = "var(--accent-red)";
    detectDot.className = "status-dot offline";
    detectBadge.style.borderColor = "rgba(255,23,68,0.3)";
    btnFlash.disabled = true;
    btnFlash.style.opacity = "0.5";
  }

  // Flash action
  btnFlash.addEventListener('click', async () => {
    const ssid = document.getElementById('espSsid').value.trim();
    const password = espPassword.value.trim();
    const backend_ip = espBackendIp.value.trim();
    
    if (!ssid || !password || !backend_ip) {
      alert("Please fill in all fields.");
      return;
    }

    // Switch to console view
    formContainer.style.display = 'none';
    consoleContainer.style.display = 'block';
    espConsole.textContent = 'Configuring payload...\n';
    btnConsoleClose.disabled = true;
    btnConsoleClose.style.opacity = '0.5';

    try {
      // 1. Configure INO
      const confRes = await fetch('/api/esp32/configure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ssid, password, backend_ip })
      });
      
      const confData = await confRes.json();
      if (confData.status !== 'ok') {
        throw new Error(confData.message || "Configuration failed");
      }
      espConsole.textContent += 'Configuration saved. Starting flash process...\n\n';

      // 2. Trigger Flash
      const flashRes = await fetch('/api/esp32/flash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}) // Uses auto-detected port
      });
      const flashData = await flashRes.json();
      if (flashData.status === 'error') {
        throw new Error(flashData.message || "Failed to start flashing");
      }

      // 3. Poll Status
      pollStatus();

    } catch (err) {
      espConsole.textContent += `\n[ERROR] ${err.message}\n`;
      btnConsoleClose.disabled = false;
      btnConsoleClose.style.opacity = '1';
    }
  });

  function pollStatus() {
    if (statusInterval) clearInterval(statusInterval);
    
    statusInterval = setInterval(async () => {
      try {
        const res = await fetch('/api/esp32/status');
        const data = await res.json();
        
        let logText = "";
        if (data.stdout) logText += data.stdout;
        if (data.stderr) logText += `\n[ERRORS]\n${data.stderr}`;
        
        espConsole.textContent = 'Configuring payload...\nConfiguration saved. Starting flash process...\n\n' + logText;
        espConsole.scrollTop = espConsole.scrollHeight; // Auto-scroll to bottom

        if (data.status === 'done' || data.status === 'error') {
          clearInterval(statusInterval);
          espConsole.textContent += `\n\n[PROCESS COMPLETE] Status: ${data.status.toUpperCase()}`;
          btnConsoleClose.disabled = false;
          btnConsoleClose.style.opacity = '1';
        }
      } catch (err) {
        clearInterval(statusInterval);
        espConsole.textContent += `\n\n[ERROR] Lost connection to backend while polling status.`;
        btnConsoleClose.disabled = false;
        btnConsoleClose.style.opacity = '1';
      }
    }, 1000);
  }

})();
