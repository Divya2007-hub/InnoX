let chart;

/* 🧠 Risk Logic */
function assessRisk(score) {
    if (score < 40) return { risk: "High Risk", className: "high" };
    if (score < 70) return { risk: "Moderate Risk", className: "medium" };
    return { risk: "Secure", className: "safe" };
}

/* 📊 Chart */
function showChart(score) {
  let ctx = document.getElementById('chart');

  if (chart) chart.destroy();

  chart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Security Score'],
      datasets: [{
        label: 'Score',
        data: [score]
      }]
    }
  });
}

/*  Status */
function updateStatus(msg) {
  document.getElementById("status").innerText = msg;
}

/* 🔍 Scan via HTTP fallback */
async function sendHttpScan(text) {
  try {
    const res = await fetch("http://127.0.0.1:8000/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ dependencies: text })
    });

    const data = await res.json();
    displayResult(data);

    updateStatus("✅ Scan complete (HTTP)");
  } catch (error) {
    updateStatus("❌ Scan failed. Start backend.");
  }
}

/* 🔍 Scan Dependencies */
function scanDependencies() {
  let input = document.getElementById("text");
  let text = input.value.trim();

  if (!text) {
    updateStatus("⚠️ Please paste or upload package.json");
    return;
  }

  addMessage("user", "🔍 Scanning dependencies...");
  updateStatus("🔍 Scanning via HTTP...");
  sendHttpScan(text);
}

/* 🛠 Fix Vulnerabilities */
async function fixVulnerabilities() {
  updateStatus("🛠 Fixing vulnerabilities...");

  try {
    const res = await fetch("http://127.0.0.1:8000/fix", {
      method: "POST"
    });

    const data = await res.json();

    addMessage("bot", "✅ Auto-fix applied successfully!");
    updateStatus("✅ Fix complete");
  } catch (error) {
    updateStatus("❌ Fix failed");
  }
}

/* 📊 Display Result */
function displayResult(data) {
  if (data.error) {
    addMessage("bot", `Error: ${data.error}`);
    updateStatus("❌ Scan error");
    document.getElementById("totalDeps").innerText = 0;
    document.getElementById("vulnCount").innerText = 0;
    document.getElementById("riskLevel").innerText = "Error";
    if (chart) chart.destroy();
    return;
  }

  let resultText = `
Score: ${data.score}
Risk: ${data.risk}
Vulnerabilities: ${data.vulnerabilities}
Fix: ${data.fix}
  `;

  addMessage("bot", resultText);

  showChart(data.score);

  // Update summary dashboard
  document.getElementById("totalDeps").innerText = data.total || 0;
  document.getElementById("vulnCount").innerText = data.vulnerabilities || 0;
  document.getElementById("riskLevel").innerText = data.risk;
}

/* 💬 Results display */
function addMessage(sender, text, extraClass = "") {
  let chat = document.getElementById("results");

  let div = document.createElement("div");
  div.className = `message ${sender} ${extraClass}`;
  div.innerText = text;

  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

/* 📂 Upload File */
function uploadFile(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();

  reader.onload = function(e) {
    document.getElementById("text").value = e.target.result;
  };

  reader.readAsText(file);
}

/* ⌨️ Enter Key */
function handleKeyPress(e) {
  if (e.key === "Enter") {
    e.preventDefault();
    scanDependencies();
  }
}

/* 🚀 Start */
