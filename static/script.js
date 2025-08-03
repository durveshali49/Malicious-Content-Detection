/*  */document.addEventListener('DOMContentLoaded', function() {
    // Get DOM elements
    const fileUpload = document.getElementById('file-upload');
    const fileUploadLabel = document.querySelector('.file-upload-label');
    const fileNameDisplay = document.getElementById('file-name');
    const scanFileBtn = document.getElementById('scan-file-btn');
    const textInput = document.getElementById('text-input');
    const scanTextBtn = document.getElementById('scan-text-btn');
    const resultsContainer = document.getElementById('results-container');
    const resultsSummary = document.getElementById('results-summary');
    const threatsList = document.getElementById('threats-list');

    let selectedFile = null;

    // File upload handler
    fileUpload.addEventListener('change', function(e) {
        if (e.target.files.length > 0) {
            selectedFile = e.target.files[0];
            fileNameDisplay.textContent = `Selected: ${selectedFile.name}`;
            scanFileBtn.disabled = false;
        } else {
            selectedFile = null;
            fileNameDisplay.textContent = '';
            scanFileBtn.disabled = true;
        }
    });

    // Scan file button handler
    scanFileBtn.addEventListener('click', function() {
        if (!selectedFile) {
            showResults('error', 'Please select a file first.');
            return;
        }

        const formData = new FormData();
        formData.append('file', selectedFile);

        // Show loading state
        scanFileBtn.disabled = true;
        scanFileBtn.textContent = 'Scanning...';

        fetch('/scan_file', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            console.log('File scan response:', data);
            if (data.error) {
                showResults('error', data.error);
            } else {
                displayResults(data.threats, data.count);
            }
        })
        .catch(error => {
            showResults('error', 'An error occurred while scanning the file.');
            console.error('Error:', error);
        })
        .finally(() => {
            // Reset button state
            scanFileBtn.disabled = false;
            scanFileBtn.textContent = 'Scan File';
        });
    });

    // Scan text button handler
    scanTextBtn.addEventListener('click', function() {
        const text = textInput.value.trim();
        if (!text) {
            showResults('error', 'Please enter some text to scan.');
            return;
        }

        // Show loading state
        scanTextBtn.disabled = true;
        scanTextBtn.textContent = 'Scanning...';

        fetch('/scan_text', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ text: text })
        })
        .then(response => response.json())
        .then(data => {
            console.log('Text scan response:', data);
            if (data.error) {
                showResults('error', data.error);
            } else {
                displayResults(data.threats, data.count);
            }
        })
        .catch(error => {
            showResults('error', 'An error occurred while scanning the text.');
            console.error('Error:', error);
        })
        .finally(() => {
            // Reset button state
            scanTextBtn.disabled = false;
            scanTextBtn.textContent = 'Scan Text';
        });
    });

    // Display scan results
    function displayResults(threats, count) {
        document.querySelector('.results-section').style.display = 'block';
        resultsContainer.style.display = 'block';
        if (!Array.isArray(threats)) threats = [];
        if (count === 0 || threats.length === 0) {
            showResults('success', 'No threats detected. The content appears to be safe.');
            threatsList.innerHTML = '';
            return;
        }
        showResults('warning', `Found ${count} potential threat(s).`);
        // Generate threats list
        threatsList.innerHTML = threats.map(threat => {
            let line = threat.line_number !== undefined ? `Line ${threat.line_number}` : '';
            let pattern = threat.pattern !== undefined ? `Pattern: ${threat.pattern}` : '';
            let content = threat.content !== undefined ? escapeHtml(threat.content) : '';
            return `<div class="threat-item">
                <div class="threat-header">
                    <span>${line}</span>
                    <span>${pattern}</span>
                </div>
                <div class="threat-content">
                    ${content}
                </div>
            </div>`;
        }).join('');
    }

    // Show results with appropriate styling
    function showResults(type, message) {
        document.querySelector('.results-section').style.display = 'block';
        resultsContainer.style.display = 'block';
        resultsSummary.className = type;
        resultsSummary.textContent = message;
        threatsList.innerHTML = '';
    }

    // Helper function to escape HTML
    function escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    }
});
