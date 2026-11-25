async function sendJson(method, url, body) {
  const csrfToken = document.querySelector('meta[name="_csrf"]');
  const csrfHeader = document.querySelector('meta[name="_csrf_header"]');
  const headers = { "Content-Type": "application/json" };
  if (csrfToken && csrfHeader) {
    headers[csrfHeader.content] = csrfToken.content;
  }
  const response = await fetch(url, {
    method,
    headers,
    body: JSON.stringify(body)
  });
  const payload = await readPayload(response);
  if (!response.ok) throw new Error(payload.message || `Request failed (${response.status})`);
  return payload.data;
}

async function postJson(url, body) {
  return sendJson("POST", url, body);
}

async function putJson(url, body) {
  return sendJson("PUT", url, body);
}

async function getJson(url) {
  const response = await fetch(url, {
    headers: { "Accept": "application/json" },
    credentials: "same-origin"
  });
  const payload = await readPayload(response);
  if (!response.ok) throw new Error(payload.message || `Request failed (${response.status})`);
  return payload.data;
}

async function deleteJson(url) {
  const csrfToken = document.querySelector('meta[name="_csrf"]');
  const csrfHeader = document.querySelector('meta[name="_csrf_header"]');
  const headers = { "Accept": "application/json" };
  if (csrfToken && csrfHeader) {
    headers[csrfHeader.content] = csrfToken.content;
  }
  const response = await fetch(url, {
    method: "DELETE",
    headers,
    credentials: "same-origin"
  });
  const payload = await readPayload(response);
  if (!response.ok) throw new Error(payload.message || `Request failed (${response.status})`);
  return payload.data;
}

async function readPayload(response) {
  if ((response.headers.get("content-type") || "").includes("application/json")) {
    return response.json();
  }
  return { message: `Request failed (${response.status})` };
}

function renderResult(elementId, data) {
  const element = document.getElementById(elementId);
  const card = document.createElement("div");
  card.className = "alert alert-dark border";
  const heading = document.createElement("strong");
  heading.textContent = data.predictedClass;
  card.append(heading, document.createTextNode(` - ${data.riskCategory} (${data.riskScore}/100)`));
  const indicators = document.createElement("ul");
  indicators.className = "mt-2 mb-0";
  const indicatorValues = data.suspiciousIndicators && data.suspiciousIndicators.length
    ? data.suspiciousIndicators
    : ["No strong indicators detected"];
  indicatorValues.forEach(value => {
    const item = document.createElement("li");
    item.textContent = value;
    indicators.append(item);
  });
  card.append(indicators);
  const details = document.createElement("small");
  details.className = "d-block mt-2 text-secondary";
  details.textContent = `${data.modelVersion} - ${data.explanation}`;
  card.append(details);
  element.replaceChildren(card);
}

function showMessage(element, message, type) {
    const alert = document.createElement("div");
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    element.replaceChildren(alert);
}

function initializeForms() {
    const registerForm = document.getElementById("register-form");
    if (registerForm) {
      registerForm.addEventListener("submit", async event => {
        event.preventDefault();
        const form = new FormData(registerForm);
        try {
          await postJson("/api/auth/register", Object.fromEntries(form));
          window.location.assign("/login?registered=true");
        } catch (error) {
          showMessage(
            document.getElementById("register-result"),
            error.message,
            "danger"
          );
        }
      });
    }

    const urlForm = document.getElementById("url-form");
    if (urlForm) {
      urlForm.addEventListener("submit", async event => {
        event.preventDefault();
        try {
          renderResult(
            "url-result",
            await postJson("/api/scan/url", {
              url: document.getElementById("url").value
            })
          );
        } catch (error) {
          showMessage(document.getElementById("url-result"), error.message, "danger");
        }
      });
    }

    const emailForm = document.getElementById("email-form");
    if (emailForm) {
      emailForm.addEventListener("submit", async event => {
        event.preventDefault();
        try {
          renderResult(
            "email-result",
            await postJson("/api/scan/email", {
              subject: document.getElementById("subject").value,
              body: document.getElementById("body").value,
              sender: document.getElementById("sender").value
            })
          );
        } catch (error) {
          showMessage(document.getElementById("email-result"), error.message, "danger");
        }
      });
    }

    const profileForm = document.getElementById("profile-update-form");
    if (profileForm) {
      profileForm.addEventListener("submit", async event => {
        event.preventDefault();
        const form = new FormData(profileForm);
        try {
          await putJson("/api/profile", {
            username: form.get("username"),
            email: form.get("email")
          });
          showMessage(document.getElementById("profile-update-result"), "Profile updated.", "success");
          await loadProfile();
        } catch (error) {
          showMessage(document.getElementById("profile-update-result"), error.message, "danger");
        }
      });
    }

    const passwordForm = document.getElementById("password-change-form");
    if (passwordForm) {
      passwordForm.addEventListener("submit", async event => {
        event.preventDefault();
        const form = new FormData(passwordForm);
        if (form.get("newPassword") !== form.get("newPasswordConfirmation")) {
          showMessage(
            document.getElementById("password-change-result"),
            "New password confirmation does not match.",
            "danger"
          );
          return;
        }
        try {
          await postJson("/api/profile/password", {
            currentPassword: form.get("currentPassword"),
            newPassword: form.get("newPassword"),
            newPasswordConfirmation: form.get("newPasswordConfirmation")
          });
          passwordForm.reset();
          showMessage(document.getElementById("password-change-result"), "Password changed successfully.", "success");
        } catch (error) {
          showMessage(document.getElementById("password-change-result"), error.message, "danger");
        }
      });
    }
}

async function loadProfile() {
    const status = document.getElementById("profile-status");
    try {
      const profile = await getJson("/api/profile");
      document.getElementById("profile-username").value = profile.username;
      document.getElementById("profile-email").value = profile.email;
      document.getElementById("profile-role").textContent = profile.role;
      document.getElementById("account-created").textContent = new Date(profile.createdAt).toLocaleString();
      status.hidden = true;
    } catch (error) {
      showMessage(status, error.message, "danger");
    }
}

async function loadDashboard() {
    const status = document.getElementById("dashboard-status");
    try {
      const dashboard = await getJson("/api/dashboard");
      const analytics = dashboard.statistics;
      document.getElementById("total-scan-count").textContent = analytics.totalScans;
      document.getElementById("url-scan-count").textContent = analytics.urlScans;
      document.getElementById("email-scan-count").textContent = analytics.emailScans;
      document.getElementById("detection-count").textContent = analytics.phishingDetections;
      document.getElementById("high-risk-count").textContent = analytics.highRiskThreats;
      document.getElementById("legitimate-count").textContent = analytics.legitimateDetections;
      status.textContent = analytics.totalScans === 0 ? "No scans recorded yet." : "";
      status.hidden = analytics.totalScans > 0;
      renderDashboardScans("recent-activity", dashboard.recentActivity, "No recent scans.");
      renderDashboardScans("latest-high-risk", dashboard.latestHighRisk, "No high-risk threats recorded.");
    } catch (error) {
      showMessage(status, error.message, "danger");
    }
}

function renderDashboardScans(elementId, scans, emptyMessage) {
    const container = document.getElementById(elementId);
    if (!scans.length) {
      container.textContent = emptyMessage;
      return;
    }
    const list = document.createElement("ul");
    list.className = "list-group list-group-flush";
    scans.forEach(scan => {
      const item = document.createElement("li");
      item.className = "list-group-item bg-transparent text-light";
      item.textContent = `#${scan.id} ${scan.scanType} — ${scan.inputSummary || "Preview unavailable"} — ${scan.riskCategory} (${scan.riskScore}/100) — ${new Date(scan.scannedAt).toLocaleString()}`;
      list.append(item);
    });
    container.replaceChildren(list);
}

async function loadHistory(formData = new FormData()) {
    const container = document.getElementById("history-content");
    try {
      const params = new URLSearchParams();
      formData.forEach((value, key) => {
        if (String(value).trim()) params.set(key, String(value).trim());
      });
      const query = params.toString();
      const scans = await getJson(`/api/history${query ? `?${query}` : ""}`);
      if (scans.length === 0) {
        container.className = "alert alert-info";
        container.textContent = "No scan records yet.";
        return;
      }

      const table = document.createElement("table");
      table.className = "table table-dark table-striped align-middle";
      const head = table.createTHead();
      const headerRow = head.insertRow();
      ["ID", "Type", "Submitted input", "Result", "Risk score", "Risk level", "Scanned", "Actions"]
        .forEach(label => {
          const cell = document.createElement("th");
          cell.scope = "col";
          cell.textContent = label;
          headerRow.append(cell);
        });

      const body = table.createTBody();
      scans.forEach(scan => {
        const row = body.insertRow();
        [scan.id, scan.scanType, scan.inputSummary || "Preview unavailable",
          scan.prediction, scan.riskScore, scan.riskCategory,
          new Date(scan.scannedAt).toLocaleString()]
          .forEach(value => {
            const cell = row.insertCell();
            cell.textContent = value;
          });
        const actions = row.insertCell();
        const detailButton = document.createElement("button");
        detailButton.className = "btn btn-sm btn-outline-info me-2";
        detailButton.type = "button";
        detailButton.textContent = "Details";
        detailButton.addEventListener("click", () => loadHistoryDetail(scan.id));
        actions.append(detailButton);

        const deleteButton = document.createElement("button");
        deleteButton.className = "btn btn-sm btn-outline-danger";
        deleteButton.type = "button";
        deleteButton.textContent = "Delete";
        deleteButton.addEventListener("click", () => deleteHistoryRecord(scan.id));
        actions.append(deleteButton);
      });
      container.className = "table-responsive";
      container.replaceChildren(table);
    } catch (error) {
      showMessage(container, error.message, "danger");
    }
}

async function loadHistoryDetail(scanId) {
    const container = document.getElementById("history-detail");
    try {
      const scan = await getJson(`/api/history/${encodeURIComponent(scanId)}`);
      const card = document.createElement("article");
      card.className = "card";
      const content = document.createElement("div");
      content.className = "card-body";
      const heading = document.createElement("h2");
      heading.className = "h5";
      heading.textContent = `Scan #${scan.id} details`;
      content.append(heading);
      [
        ["Type", scan.scanType],
        ["Submitted input", scan.inputSummary || "Preview unavailable"],
        ["Result", scan.prediction],
        ["Risk level", scan.riskCategory],
        ["Risk score", `${scan.riskScore}/100`],
        ["Scanned", new Date(scan.scannedAt).toLocaleString()]
      ].forEach(([label, value]) => {
        const paragraph = document.createElement("p");
        paragraph.textContent = `${label}: ${value}`;
        content.append(paragraph);
      });
      const indicatorHeading = document.createElement("h3");
      indicatorHeading.className = "h6";
      indicatorHeading.textContent = "Detection reasons";
      content.append(indicatorHeading);
      const indicators = document.createElement("ul");
      (scan.indicators || []).forEach(indicator => {
        const item = document.createElement("li");
        item.textContent = indicator;
        indicators.append(item);
      });
      if (!indicators.childElementCount) {
        const item = document.createElement("li");
        item.textContent = "No strong indicators detected";
        indicators.append(item);
      }
      content.append(indicators);
      card.append(content);
      container.replaceChildren(card);
    } catch (error) {
      showMessage(container, error.message, "danger");
    }
}

async function deleteHistoryRecord(scanId) {
    if (!window.confirm(`Delete scan #${scanId}? This cannot be undone.`)) return;
    try {
      await deleteJson(`/api/history/${encodeURIComponent(scanId)}`);
      document.getElementById("history-detail").replaceChildren();
      await loadHistory(new FormData(document.getElementById("history-filter-form")));
    } catch (error) {
      showMessage(document.getElementById("history-content"), error.message, "danger");
    }
}

async function loadAnalytics() {
    const status = document.getElementById("analytics-status");
    try {
      const analytics = await getJson("/api/analytics");
      document.getElementById("total-scans").textContent = analytics.totalScans;
      document.getElementById("phishing-detections").textContent = analytics.phishingDetections;
      document.getElementById("high-risk-threats").textContent = analytics.highRiskThreats;
      document.getElementById("analytics-url-scans").textContent = analytics.urlScans;
      document.getElementById("analytics-email-scans").textContent = analytics.emailScans;
      document.getElementById("legitimate-detections").textContent = analytics.legitimateDetections;
      drawBarChart(
        "daily-activity-chart",
        analytics.dailyActivity.map(item => item.date.slice(5)),
        analytics.dailyActivity.map(item => item.totalScans),
        ["#35c5ff"]
      );
      drawBarChart(
        "risk-distribution-chart",
        ["LOW", "MEDIUM", "HIGH"],
        [
          analytics.riskDistribution.low,
          analytics.riskDistribution.medium,
          analytics.riskDistribution.high
        ],
        ["#42d3a0", "#f6c85f", "#ff6174"]
      );
      drawBarChart(
        "scan-type-chart",
        ["URL", "EMAIL"],
        [analytics.scanTypeComparison.urlScans, analytics.scanTypeComparison.emailScans],
        ["#35c5ff", "#42d3a0"]
      );
      status.hidden = true;
    } catch (error) {
      showMessage(status, error.message, "danger");
    }
}

function drawBarChart(canvasId, labels, values, colors) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const context = canvas.getContext("2d");
    if (!context) return;

    const width = Math.max(canvas.clientWidth, 320);
    const height = 260;
    const ratio = window.devicePixelRatio || 1;
    canvas.width = width * ratio;
    canvas.height = height * ratio;
    context.scale(ratio, ratio);
    context.clearRect(0, 0, width, height);

    const left = 40;
    const right = 12;
    const top = 14;
    const bottom = 38;
    const chartWidth = width - left - right;
    const chartHeight = height - top - bottom;
    const maximum = Math.max(...values, 1);
    context.font = "12px sans-serif";
    context.textAlign = "right";
    context.textBaseline = "middle";
    context.fillStyle = "#9fb3c8";
    context.strokeStyle = "#254a69";
    for (let step = 0; step <= 4; step++) {
      const y = top + chartHeight * step / 4;
      const value = Math.round(maximum * (4 - step) / 4);
      context.fillText(String(value), left - 8, y);
      context.beginPath();
      context.moveTo(left, y);
      context.lineTo(width - right, y);
      context.stroke();
    }

    const slotWidth = chartWidth / Math.max(labels.length, 1);
    const barWidth = Math.min(42, slotWidth * 0.6);
    labels.forEach((label, index) => {
      const value = values[index] || 0;
      const barHeight = chartHeight * value / maximum;
      const x = left + slotWidth * index + (slotWidth - barWidth) / 2;
      const y = top + chartHeight - barHeight;
      context.fillStyle = colors[index % colors.length];
      context.fillRect(x, y, barWidth, barHeight);
      context.textAlign = "center";
      context.textBaseline = "bottom";
      context.fillStyle = "#e8f1f8";
      context.fillText(String(value), x + barWidth / 2, Math.max(top, y - 4));
      context.textBaseline = "top";
      context.fillStyle = "#9fb3c8";
      context.fillText(label, x + barWidth / 2, top + chartHeight + 8);
    });
}

function initializePage() {
    initializeForms();
    if (document.getElementById("dashboard-status")) loadDashboard();
    if (document.getElementById("profile-status")) loadProfile();
    const historyFilter = document.getElementById("history-filter-form");
    if (historyFilter) {
      historyFilter.addEventListener("submit", event => {
        event.preventDefault();
        loadHistory(new FormData(historyFilter));
      });
      historyFilter.addEventListener("reset", () => {
        window.setTimeout(() => loadHistory(new FormData(historyFilter)), 0);
      });
      loadHistory(new FormData(historyFilter));
    }
    if (document.getElementById("analytics-status")) loadAnalytics();
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initializePage);
} else {
    initializePage();
}
