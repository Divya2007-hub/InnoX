let chart;
let scanInProgress = false;
let fixInProgress = false;

function assessRisk(score) {
    if (score < 40) return { risk: "High Risk", className: "high" };
    if (score < 70) return { risk: "Moderate Risk", className: "medium" };
    return { risk: "Secure", className: "safe" };
}

function showChart(score) {
  const ctx = document.getElementById('chart');

  if (chart) chart.destroy();

  chart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Security Score'],
      datasets: [{
        label: 'Score',
        data: [score],
        backgroundColor: score < 40 ? '#ff5a5a' : score < 70 ? '#ffb347' : '#7effa8',
        borderRadius: 10,
        barThickness: 40,
        maxBarThickness: 60,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          max: 100,
          ticks: {
            color: '#00ff9f'
          },
          grid: {
            color: 'rgba(0,255,159,0.1)'
          }
        },
        x: {
          ticks: {
            color: '#00ff9f'
          },
          grid: {
            display: false
          }
        }
      },
      plugins: {
        legend: {
          labels: {
            color: '#00ff9f'
          }
        }
      }
    }
  });
}

function updateStatus(msg) {
  document.getElementById("status").innerText = msg;
}

async function sendHttpScan(text, auto = false) {
  try {
    const res = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ dependencies: text })
    });

    const data = await res.json();
    if (!res.ok || data.error) {
      throw new Error(data.error || 'Scan request failed');
    }

    displayResult(data);
    updateStatus(auto ? "✅ Auto scan complete" : "✅ Scan complete");
    return data;
  } catch (error) {
    updateStatus(`❌ Scan failed: ${error.message}`);
    if (!auto) {
      addMessage("bot", `Error: ${error.message}`);
    }
    return null;
  }
}

function scanDependencies(auto = false) {
  const input = document.getElementById("text");
  const text = input.value.trim();

  if (!text) {
    updateStatus("⚠️ Please paste or upload package.json");
    return;
  }

  if (!auto) {
    addMessage("user", "🔍 Scanning dependencies...");
  }

  updateStatus("🔍 Scanning...");
  return sendHttpScan(text, auto);
}

async function fixVulnerabilities(auto = false) {
  fixInProgress = true;
  updateStatus("🛠 Fixing vulnerabilities...");

  try {
    const res = await fetch("/fix", {
      method: "POST"
    });

    const data = await res.json();
    if (!res.ok || data.error) {
      throw new Error(data.error || data.message || 'Fix failed');
    }

    const result = data.result || data;
    if (!auto) {
      addMessage("bot", `✅ Fix complete. ${data.message || ''}`);
    }
    displayResult(result);
    updateStatus(auto ? "✅ Auto fix applied" : "✅ Fix applied");
    return result;
  } catch (error) {
    updateStatus(`❌ Fix failed: ${error.message}`);
    if (!auto) {
      addMessage("bot", `Error: ${error.message}`);
    }
    return null;
  } finally {
    fixInProgress = false;
  }
}

function displayResult(data) {
  const payload = data.result || data;

  if (payload.error) {
    addMessage("bot", `Error: ${payload.error}`);
    updateStatus("❌ Scan error");
    document.getElementById("totalDeps").innerText = 0;
    document.getElementById("vulnCount").innerText = 0;
    document.getElementById("riskLevel").innerText = "Error";
    if (chart) chart.destroy();
    return;
  }

  const riskInfo = assessRisk(payload.score ?? 0);
  const resultText = `Score: ${payload.score}
Risk: ${payload.risk || riskInfo.risk}
Vulnerabilities: ${payload.vulnerabilities}
Fix: ${payload.fix || payload.message || 'N/A'}`;

  addMessage("bot", resultText);
  showChart(payload.score ?? 0);

  document.getElementById("totalDeps").innerText = payload.total_dependencies ?? payload.total ?? 0;
  document.getElementById("vulnCount").innerText = payload.vulnerabilities ?? 0;
  const riskLabel = payload.risk || riskInfo.risk;
  const riskElement = document.getElementById("riskLevel");
  riskElement.innerText = riskLabel;
  riskElement.className = riskInfo.className;
}

function addMessage(sender, text) {
  const chat = document.getElementById("results");
  const div = document.createElement("div");
  div.className = `message ${sender}`;
  div.innerText = text;
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

function uploadFile(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function(e) {
    document.getElementById("text").value = e.target.result;
  };
  reader.readAsText(file);
}

async function loadPackageFile() {
  try {
    const res = await fetch("/package");
    const data = await res.json();
    if (res.ok && data.content) {
      document.getElementById("text").value = data.content;
    }
  } catch (error) {
    console.warn("Package load failed", error);
  }
}

async function autoScanAndFix() {
  if (scanInProgress || fixInProgress) return;

  await loadPackageFile();
  const input = document.getElementById("text");
  const text = input.value.trim();
  if (!text) return;

  const data = await scanDependencies(true);
  if (data && data.vulnerabilities > 0) {
    await fixVulnerabilities(true);
  }
}

async function loadStatus() {
  try {
    const res = await fetch("/status");
    const data = await res.json();
    if (!res.ok || data.error) {
      throw new Error(data.error || 'Unable to load status');
    }
    displayResult(data);
    updateStatus("✅ Live status loaded");
  } catch (error) {
    updateStatus(`❌ Status unavailable: ${error.message}`);
  }
}

window.addEventListener('DOMContentLoaded', () => {
  loadStatus();
  autoScanAndFix();
  setInterval(autoScanAndFix, 60000);

  document.getElementById('text').addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && e.ctrlKey) {
      e.preventDefault();
      scanDependencies();
    }
  });
});
