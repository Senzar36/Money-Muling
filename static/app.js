const fileInput = document.getElementById("csvFile");
const analyzeButton = document.getElementById("analyzeButton");
const searchButton = document.getElementById("searchButton");
const statusBox = document.getElementById("status");
const resultsBox = document.getElementById("results");
const entityResult = document.getElementById("entityResult");

let graph;

analyzeButton.addEventListener("click", analyze);
searchButton.addEventListener("click", searchEntity);

async function analyze() {
    const file = fileInput.files[0];

    if (!file) {
        setStatus("Choose a CSV file first.", "error");
        return;
    }

    const formData = new FormData();
    formData.append("file", file);

    setStatus("Analyzing transaction network...", "");
    analyzeButton.disabled = true;

    try {
        const response = await fetch("/upload", {
            method: "POST",
            body: formData,
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Analysis failed.");
        }

        updateSummary(data.summary, data.fraud_rings);
        renderResults(data.fraud_rings);
        renderGraph(data.graph_elements);
        setStatus("Analysis complete.", "success");
    } catch (error) {
        setStatus(error.message, "error");
    } finally {
        analyzeButton.disabled = false;
    }
}

async function searchEntity() {
    const id = document.getElementById("searchInput").value.trim();

    if (!id) return;

    try {
        const response = await fetch(`/search?id=${encodeURIComponent(id)}`);
        const data = await response.json();

        if (!data.found) {
            entityResult.innerHTML = `<p><strong>${escapeHtml(id)}</strong> was not found.</p>`;
            return;
        }

        const details = data.details;
        entityResult.innerHTML = `
            <p><strong>${escapeHtml(details.account_id)}</strong></p>
            <p>Pattern: ${escapeHtml(details.pattern)}</p>
            <p>Score: ${details.score}%</p>
            <p>${escapeHtml(details.math)}</p>
        `;
    } catch {
        entityResult.innerHTML = "<p>Search failed. Try again.</p>";
    }
}

function updateSummary(summary, rings) {
    document.getElementById("nodeCount").textContent = summary.total_nodes ?? "—";
    document.getElementById("edgeCount").textContent = summary.total_edges ?? "—";
    document.getElementById("ringCount").textContent = rings.length;
}

function renderResults(rings) {
    if (!rings.length) {
        resultsBox.innerHTML = '<p class="muted">No 3–5 node cycles detected.</p>';
        return;
    }

    resultsBox.innerHTML = rings.map(ring => `
        <div class="result-row">
            <div>
                <strong>${escapeHtml(ring.ring_id)}</strong><br>
                <span class="muted">${ring.members.length} accounts</span>
            </div>
            <span class="score">${ring.score}%</span>
        </div>
    `).join("");
}

function renderGraph(elements) {
    if (graph) graph.destroy();

    graph = cytoscape({
        container: document.getElementById("cy"),
        elements,
        style: [
            {
                selector: "node",
                style: {
                    "background-color": "data(status)",
                    "label": "data(id)",
                    "color": "#dfe7ee",
                    "font-size": 8,
                    "text-outline-width": 2,
                    "text-outline-color": "#0b0f14",
                    "width": 22,
                    "height": 22,
                },
            },
            {
                selector: "node[status = 'high-risk']",
                style: { "background-color": "#ef6b73" },
            },
            {
                selector: "node[status = 'medium-risk']",
                style: { "background-color": "#e8b84a" },
            },
            {
                selector: "node[status = 'normal']",
                style: { "background-color": "#49b883" },
            },
            {
                selector: "edge",
                style: {
                    "width": 1.5,
                    "line-color": "#3b4652",
                    "target-arrow-shape": "triangle",
                    "target-arrow-color": "#3b4652",
                    "curve-style": "bezier",
                    "opacity": 0.7,
                },
            },
        ],
        layout: {
            name: "cose",
            padding: 50,
            nodeRepulsion: 7000,
            idealEdgeLength: 80,
        },
    });

    const tooltip = document.getElementById("tooltip");

    graph.on("mouseover", "node", event => {
        const data = event.target.data();
        tooltip.innerHTML = `
            <strong>${escapeHtml(data.id)}</strong><br>
            Risk: ${data.score}%<br>
            Pattern: ${escapeHtml(data.pattern)}
        `;
        tooltip.style.display = "block";
    });

    graph.on("mousemove", "node", event => {
        tooltip.style.left = `${event.renderedPosition.x + 20}px`;
        tooltip.style.top = `${event.renderedPosition.y + 20}px`;
    });

    graph.on("mouseout", "node", () => {
        tooltip.style.display = "none";
    });
}

function setStatus(message, type) {
    statusBox.textContent = message;
    statusBox.className = `status ${type}`;
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}
