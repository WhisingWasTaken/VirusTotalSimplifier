const getElement = id => document.getElementById(id);

const updateResult = (content, display = true) => {
    const result = getElement('result');
    result.style.display = display ? 'block' : 'none';
    result.innerHTML = content;
};

const showLoading = message => updateResult(`
    <div class="loading">
        <p>${message}</p>
        <div class="spinner"></div>
    </div>
`);

const showError = message => updateResult(`<p class="error">${message}</p>`);

async function makeRequest(endpoint, data = {}, method = 'POST') {
    try {
        const response = await fetch(endpoint, {
            method: method,
            headers: {
                'Content-Type': 'application/json',
            },
            body: method === 'GET' ? undefined : JSON.stringify(data)
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({ 
                error: { message: `HTTP ${response.status}: ${response.statusText}` } 
            }));
            throw new Error(error.error?.message || 'Request failed!');
        }

        return await response.json();
    } catch (error) {
        throw new Error(`Network error: ${error.message}`);
    }
}

async function scanurl() {
    const urlInput = getElement('url-input');
    let url = urlInput.value.trim();
    
    if (!url) {
        showError("Please enter a URL!");
        return;
    }

    try {
        if (!url.startsWith('http')) {
            url = 'https://' + url;
            urlInput.value = url;
        }
        new URL(url);
    } catch {
        showError("Please enter a valid URL (e.g., youtube.com, https://youtube.com)");
        return;
    }

    try {
        showLoading("Submitting URL for scanning...");

        const submitResult = await makeRequest('/.netlify/functions/virustotal-url', {
            url: url
        });

        if (!submitResult.data?.id) {
            throw new Error("Failed to get analysis ID");
        }

        await new Promise(resolve => setTimeout(resolve, 3000));

        showLoading("Getting scan results...");
        await pollAnalysisResults(submitResult.data.id);
    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

async function scanfile() {
    const fileInput = getElement('file-input');
    const file = fileInput.files[0];
    
    if (!file) {
        showError("Please select a file!");
        return;
    }
    
    if (file.size > 32 * 1024 * 1024) {
        showError("File size exceeds 32MB limit.");
        return;
    }

    try {
        showLoading("Uploading file...");
        console.log('Starting file upload:', file.name, 'Size:', file.size, 'Type:', file.type);

        const formData = new FormData();
        formData.append("file", file, file.name);
        
        console.log('FormData created, sending to Netlify function...');

        const response = await fetch('/.netlify/functions/virustotal-file', {
            method: 'POST',
            body: formData
        });

        console.log('Response received:', response.status, response.statusText);
        
        if (!response.ok) {
            let errorMessage = `Upload failed (${response.status})`;
            try {
                const errorData = await response.json();
                console.log('Error data:', errorData);
                errorMessage = errorData.error || errorData.message || errorMessage;
            } catch (e) {
                console.error('Could not parse error response:', e);
            }
            throw new Error(errorMessage);
        }

        const uploadResult = await response.json();
        console.log('Upload successful:', uploadResult);

        if (!uploadResult.data?.id) {
            console.error('No analysis ID in response:', uploadResult);
            throw new Error("Failed to get file ID from VirusTotal!");
        }

        showLoading("Processing file...");
        await new Promise(resolve => setTimeout(resolve, 3000));

        showLoading("Getting scan results...");
        
        const analysisResult = await makeRequest('/.netlify/functions/virustotal-analysis', {
            analysisId: uploadResult.data.id
        });

        if (!analysisResult.data?.id) {
            throw new Error("Failed to get analysis results!");
        }

        await pollAnalysisResults(analysisResult.data.id, file.name);
        
    } catch (error) {
        console.error('File scan error:', error);
        showError(`Error: ${error.message}`);
    }
}

async function pollAnalysisResults(analysisId, fileName = '') {
    const maxAttempts = 20;
    let attempts = 0;
    let interval = 2000;

    while (attempts < maxAttempts) {
        try {
            const remainingTime = ((maxAttempts - attempts) * interval / 1000).toFixed(0);
            showLoading(`Analyzing${fileName ? ` ${fileName}` : ''}... (${remainingTime}s remaining)`);

            const report = await makeRequest('/.netlify/functions/virustotal-analysis', {
                analysisId: analysisId
            });
            
            const status = report.data?.attributes?.status;

            if (!status) {
                throw new Error("Invalid analysis response!");
            }

            if (status === "completed") {
                showFormattedResult(report);
                break;
            }

            if (status === "failed") {
                throw new Error("Analysis failed!");
            }

            attempts++;
            
            if (attempts >= maxAttempts) {
                throw new Error("Analysis timeout - please try again!");
            }

            interval = Math.min(interval * 1.5, 8000);
            await new Promise(resolve => setTimeout(resolve, interval));
        } catch (error) {
            showError(`Error: ${error.message}`);
            break;
        }
    }
}

function showFormattedResult(data) {
    if (!data?.data?.attributes?.stats) {
        showError("Invalid response format!");
        return;
    }

    const stats = data.data.attributes.stats;
    const total = Object.values(stats).reduce((sum, val) => sum + val, 0);
    
    if (!total) {
        showError("No analysis results available!");
        return;
    }

    const getPercent = val => ((val / total) * 100).toFixed(1);

    const categories = {
        malicious: { color: 'malicious', label: 'Malicious' },
        suspicious: { color: 'suspicious', label: 'Suspicious' },
        harmless: { color: 'safe', label: 'Clean' },
        undetected: { color: 'undetected', label: 'Undetected' }
    };

    const percents = Object.keys(categories).reduce((acc, key) => {
        acc[key] = getPercent(stats[key] || 0);
        return acc;
    }, {});

    const verdict = stats.malicious > 0 ? "Malicious" : 
                   stats.suspicious > 0 ? "Suspicious" : "Safe";
    const verdictClass = stats.malicious > 0 ? "malicious" : 
                        stats.suspicious > 0 ? "suspicious" : "safe";

    updateResult(`
        <h3>Scan Report</h3>
        <div class="scan-stats">
            <p><strong>Verdict:</strong> <span class="verdict ${verdictClass}">${verdict}</span></p>
            <div class="progress-section">
                <div class="progress-label">
                    <span>Detection Results</span>
                    <span class="progress-percent">${percents.malicious}% Detection Rate</span>
                </div>
                <div class="progress-stacked">
                    ${Object.entries(categories).map(([key, { color }]) => `
                        <div class="progress-bar ${color}" style="width: ${percents[key]}%" title="${categories[key].label}: ${stats[key] || 0} (${percents[key]}%)">
                            <span class="progress-label-overlay">${stats[key] || 0}</span>
                        </div>
                    `).join('')}
                </div>
                <div class="progress-legend">
                    ${Object.entries(categories).map(([key, { color, label }]) => `
                        <div class="legend-item">
                            <span class="legend-color ${color}"></span>
                            <span>${label} (${percents[key]}%)</span>
                        </div>
                    `).join('')}
                </div>
            </div>
            <div class="detection-details">
                ${Object.entries(categories).map(([key, { color, label }]) => `
                    <div class="detail-item ${color}">
                        <span class="detail-label">${label}</span>
                        <span class="detail-value">${stats[key] || 0}</span>
                        <span class="detail-percent">${percents[key]}%</span>
                    </div>
                `).join('')}
            </div>
        </div>
        <button onclick="showFullReport(this.getAttribute('data-report'))" data-report='${JSON.stringify(data)}'>View Full Report</button>
    `);

    setTimeout(() => {
        const progressStacked = getElement('result').querySelector('.progress-stacked');
        if (progressStacked) {
            progressStacked.classList.add('animate');
        }
    }, 100);
}

function showFullReport(reportData) {
    const data = typeof reportData === 'string' ? JSON.parse(reportData) : reportData;
    const modal = getElement("full-report-modal");
    const results = data.data?.attributes?.results;

    if (!results) {
        getElement("full-report-content").innerHTML = `
            <h3>Full Report Details</h3>
            <p>No detailed results available!</p>
            <span class="close" onclick="closeModal()">&times;</span>
        `;
    } else {
        getElement("full-report-content").innerHTML = `
            <h3>Full Report Details</h3>
            <table>
                <thead>
                    <tr><th>Engine</th><th>Result</th></tr>
                </thead>
                <tbody>
                    ${Object.entries(results).map(([engine, result]) => `
                        <tr>
                            <td>${engine}</td>
                            <td class="${result.category === "malicious" ? "malicious" : result.category === "suspicious" ? "suspicious" : "safe"}">
                                ${result.category || 'N/A'}
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
            <span class="close" onclick="closeModal()">&times;</span>
        `;
    }

    modal.style.display = "block";
    modal.offsetHeight;
    modal.classList.add("show");
}

function closeModal() {
    const modal = getElement("full-report-modal");
    modal.classList.remove("show");
    setTimeout(() => {
        modal.style.display = "none";
    }, 300);
}

const themeToggle = document.getElementById("theme-toggle");
const buttonColorPicker = document.getElementById("button-color");

window.addEventListener("load", () => {
    const savedTheme = localStorage.getItem("theme");
    const savedColor = localStorage.getItem("buttonColor");

    if (savedTheme === "dark") {
        document.body.classList.add("dark");
        if (themeToggle) {
            themeToggle.textContent = "Switch to Light Mode";
        }
    }

    if (savedColor && buttonColorPicker) {
        document.documentElement.style.setProperty("--primary-color", savedColor);
        document.documentElement.style.setProperty("--primary-hover", shadeColor(savedColor, -15));
        buttonColorPicker.value = savedColor;
    }

    const modal = getElement("full-report-modal");
    
    if (modal) {
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                closeModal();
            }
        });
        
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && modal.style.display === 'block') {
                closeModal();
            }
        });
    }
});

if (themeToggle) {
    themeToggle.addEventListener("click", () => {
        document.body.classList.toggle("dark");
        const isDark = document.body.classList.contains("dark");
        themeToggle.textContent = isDark ? "Switch to Light Mode" : "Switch to Dark Mode";
        localStorage.setItem("theme", isDark ? "dark" : "light");
    });
}

if (buttonColorPicker) {
    buttonColorPicker.addEventListener("input", (e) => {
        const newColor = e.target.value;
        document.documentElement.style.setProperty("--primary-color", newColor);
        document.documentElement.style.setProperty("--primary-hover", shadeColor(newColor, -15));
        localStorage.setItem("buttonColor", newColor);
    });
}

function shadeColor(color, percent) {
    if (!color || color.length !== 7 || !color.startsWith('#')) {
        return color;
    }

    try {
        let R = parseInt(color.substring(1, 3), 16);
        let G = parseInt(color.substring(3, 5), 16);
        let B = parseInt(color.substring(5, 7), 16);

        R = parseInt(R * (100 + percent) / 100);
        G = parseInt(G * (100 + percent) / 100);
        B = parseInt(B * (100 + percent) / 100);

        R = (R < 255) ? R : 255;
        G = (G < 255) ? G : 255;
        B = (B < 255) ? B : 255;

        const RR = ((R.toString(16).length == 1) ? "0" + R.toString(16) : R.toString(16));
        const GG = ((G.toString(16).length == 1) ? "0" + G.toString(16) : G.toString(16));
        const BB = ((B.toString(16).length == 1) ? "0" + B.toString(16) : B.toString(16));

        return "#" + RR + GG + BB;
    } catch (error) {
        console.error("Error shading color:", error);
        return color;
    }
}

window.addEventListener('DOMContentLoaded', () => {
    const urlInput = getElement('url-input');
    if (urlInput) {
        urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                scanurl();
            }
        });
    }

    const fileInput = getElement('file-input');
    if (fileInput) {
        fileInput.addEventListener('change', () => {
            const fileName = fileInput.files[0]?.name;
            if (fileName) {
                console.log(`File selected: ${fileName}`);
            }
        });
    }
});

window.scanurl = scanurl;
window.scanfile = scanfile;
window.showFullReport = showFullReport;
window.closeModal = closeModal;