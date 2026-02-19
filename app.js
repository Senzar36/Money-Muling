// app.js
import cytoscape from 'cytoscape';

async function uploadAndVisualize(file) {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch('/analyze', { method: 'POST', body: formData });
    const rings = await response.json();

    // Prepare elements for Cytoscape
    const elements = [];
    rings.forEach(ring => {
        ring.members.forEach(id => {
            elements.push({ data: { id, label: id } });
        });
        // Create edges for the ring
        for (let i = 0; i < ring.members.length; i++) {
            const source = ring.members[i];
            const target = ring.members[(i + 1) % ring.members.length];
            elements.push({ data: { id: `${source}-${target}`, source, target } });
        }
    });

    // Initialize the Graph
    const cy = cytoscape({
        container: document.getElementById('cy'),
        elements: elements,
        style: [
            {
                selector: 'node',
                style: { 'background-color': '#ff4d4d', 'label': 'data(id)', 'color': '#fff' }
            },
            {
                selector: 'edge',
                style: { 'width': 3, 'line-color': '#ccc', 'target-arrow-shape': 'triangle' }
            }
        ],
        layout: { name: 'circle' }
    });
}