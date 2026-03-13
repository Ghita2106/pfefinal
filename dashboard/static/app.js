let barChart = null;

let allAlerts = [];
let currentPage = 1;
const alertsPerPage = 10;

function buildBarChart(stats) {
    const canvas = document.getElementById("attackBarChart");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");

    if (barChart) {
        barChart.destroy();
    }

    barChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels: ["SQLi", "Bruteforce"],
            datasets: [
                {
                    label: "Nombre d'alertes",
                    data: [
                        stats.sqli || 0,
                        stats.bruteforce || 0
                    ],
                    backgroundColor: [
                        "#ef4444",
                        "#f59e0b"
                    ]
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: "#e2e8f0"
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: "#e2e8f0" },
                    grid: { color: "#1f2937" }
                },
                y: {
                    beginAtZero: true,
                    ticks: { color: "#e2e8f0" },
                    grid: { color: "#1f2937" }
                }
            }
        }
    });
}

function renderTopIps(topIps) {
    const container = document.getElementById("top-ips");
    if (!container) return;

    if (!topIps || topIps.length === 0) {
        container.innerHTML = "<p>Aucune donnée disponible.</p>";
        return;
    }

    let html = '<ul class="ip-list">';
    for (const [ip, count] of topIps) {
        html += `<li><span>${ip}</span><strong>${count}</strong></li>`;
    }
    html += "</ul>";
    container.innerHTML = html;
}

function renderAlertsPage() {
    const tbody = document.getElementById("alerts-table-body");
    const pageInfo = document.getElementById("page-info");
    const prevBtn = document.getElementById("prev-page");
    const nextBtn = document.getElementById("next-page");

    if (!tbody) return;

    if (!allAlerts || allAlerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7">Aucune alerte détectée.</td></tr>`;
        if (pageInfo) pageInfo.textContent = "Page 1";
        if (prevBtn) prevBtn.disabled = true;
        if (nextBtn) nextBtn.disabled = true;
        return;
    }

    const totalPages = Math.max(1, Math.ceil(allAlerts.length / alertsPerPage));

    if (currentPage > totalPages) {
        currentPage = totalPages;
    }

    const start = (currentPage - 1) * alertsPerPage;
    const end = start + alertsPerPage;
    const alertsToShow = allAlerts.slice(start, end);

    let html = "";

    for (const alert of alertsToShow) {
        html += `
            <tr>
                <td><span class="badge ${alert.type}">${alert.type}</span></td>
                <td>${alert.confidence ?? ""}</td>
                <td>${alert.ip ?? ""}</td>
                <td>${alert.timestamp ?? ""}</td>
                <td>${alert.method ?? ""}</td>
                <td class="url-cell">${alert.url ?? ""}</td>
                <td>${alert.status ?? ""}</td>
            </tr>
        `;
    }

    tbody.innerHTML = html;

    if (pageInfo) {
        pageInfo.textContent = `Page ${currentPage} / ${totalPages}`;
    }

    if (prevBtn) {
        prevBtn.disabled = currentPage === 1;
    }

    if (nextBtn) {
        nextBtn.disabled = currentPage === totalPages;
    }
}

function updateStats(stats) {
    const totalAlerts = document.getElementById("total-alerts");
    const sqliCount = document.getElementById("sqli-count");
    const bruteforceCount = document.getElementById("bruteforce-count");
    const uniqueIps = document.getElementById("unique-ips");
    const sqliPercent = document.getElementById("sqli-percent");
    const bruteforcePercent = document.getElementById("bruteforce-percent");
    const percentSqli = document.getElementById("percent-sqli");
    const percentBruteforce = document.getElementById("percent-bruteforce");
    const riskLabel = document.getElementById("risk-label");
    const riskScore = document.getElementById("risk-score");
    const riskBar = document.getElementById("risk-bar");

    if (totalAlerts) totalAlerts.textContent = stats.total || 0;
    if (sqliCount) sqliCount.textContent = stats.sqli || 0;
    if (bruteforceCount) bruteforceCount.textContent = stats.bruteforce || 0;
    if (uniqueIps) uniqueIps.textContent = stats.unique_ips || 0;
    if (sqliPercent) sqliPercent.textContent = `${stats.sqli_percent || 0}%`;
    if (bruteforcePercent) bruteforcePercent.textContent = `${stats.bruteforce_percent || 0}%`;
    if (percentSqli) percentSqli.textContent = `${stats.sqli_percent || 0}%`;
    if (percentBruteforce) percentBruteforce.textContent = `${stats.bruteforce_percent || 0}%`;
    if (riskLabel) riskLabel.textContent = stats.risk_label || "Aucun risque";
    if (riskScore) riskScore.textContent = stats.risk_score || 0;
    if (riskBar) riskBar.style.width = `${stats.risk_score || 0}%`;
}

async function refreshDashboard() {
    try {
        const response = await fetch("/api/alerts");
        const data = await response.json();

        allAlerts = data.alerts || [];

        updateStats(data.stats);
        renderTopIps(data.stats.top_ips);
        renderAlertsPage();
        buildBarChart(data.stats);
    } catch (error) {
        console.error("Erreur lors du rafraîchissement :", error);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    allAlerts = initialAlerts || [];
    buildBarChart(initialStats || {});
    renderAlertsPage();

    const prevBtn = document.getElementById("prev-page");
    const nextBtn = document.getElementById("next-page");

    if (prevBtn) {
        prevBtn.addEventListener("click", () => {
            if (currentPage > 1) {
                currentPage--;
                renderAlertsPage();
            }
        });
    }

    if (nextBtn) {
        nextBtn.addEventListener("click", () => {
            const totalPages = Math.max(1, Math.ceil(allAlerts.length / alertsPerPage));
            if (currentPage < totalPages) {
                currentPage++;
                renderAlertsPage();
            }
        });
    }

    refreshDashboard();
    setInterval(refreshDashboard, 5000);
});
