async function analyzeRepo() {
    const githubUrl = document.getElementById('githubUrl').value;
    const loading = document.getElementById('loading');
    const dashboard = document.getElementById('dashboard');

    // Add GitHub URL validation regex
    const githubRegex = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+(?:\.git)?$/;
    
    if (!githubUrl) {
        alert('Please enter a GitHub repository URL');
        return;
    }
    
    if (!githubRegex.test(githubUrl)) {
        alert('Please enter a valid GitHub repository URL in the format: https://github.com/owner/repo.git');
        return;
    }

    try {
        loading.classList.remove('hidden');
        dashboard.classList.add('hidden');

        const response = await fetch('http://localhost:4000/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ githubUrl })
        });

        if (!response.ok) {
            throw new Error('Analysis failed');
        }

        const data = await response.json();
        console.log("data: ", data);
        displayResults(data);
    } catch (error) {
        alert('Error analyzing repository: ' + error.message);
    } finally {
        loading.classList.add('hidden');
    }
}

function displayResults(data) {
    console.log("displaying results...");
    const dashboard = document.getElementById('dashboard');
    const threatModel = document.getElementById('threatModel');
    const vulnCards = document.getElementById('vulnCards');

    // Display threat model
    threatModel.innerHTML = marked.parse(data.threatModel);

    // Display vulnerabilities
    vulnCards.innerHTML = '';

    // Parse the data if it's a string
    const { vulnerabilities } = data;
 
    vulnerabilities.forEach(vuln => {
        console.log("vuln: ", vuln);
        vulnCards.appendChild(createVulnCard(vuln));
    });

    dashboard.classList.remove('hidden');
}

function createVulnCard(vuln) {
    console.log("creating vuln card for vuln: ", vuln.packageName);
    const card = document.createElement('div');
    card.className = 'vuln-card';
    
    card.innerHTML = `
        <h3>${vuln.packageName}</h3>
        <span class="risk-level risk-${vuln.vulnerability.contextualRiskLevel.toLowerCase()}">
            AI Risk Assessment: ${vuln.vulnerability.contextualRiskLevel.toUpperCase()}
        </span>
        <p><strong>Summary:</strong> ${vuln.vulnerability.summary}</p>
        
        <div class="exploitability-section">
            <h4>Exploitability Assessment</h4>
            <p><strong>Is Exploitable:</strong> ${vuln.vulnerability.isExploitable ? 'Yes' : 'No'}</p>
            <p><strong>Reasoning:</strong> ${vuln.vulnerability.exploitabilityReasoning}</p>
        </div>

        ${vuln.vulnerability.requiredConditions.length > 0 ? `
            <div class="conditions-section">
                <h4>Required Conditions</h4>
                <ul>
                    ${vuln.vulnerability.requiredConditions.map(condition => 
                        `<li>${condition}</li>`
                    ).join('')}
                </ul>
            </div>` : ''}

            <div class="mitigations-section">
                <details class="mitigations-dropdown">
                    <summary>Recommended Mitigations</summary>
                    <ul>
                        ${vuln.vulnerability.recommendedMitigations.map(mitigation => 
                            `<li>${mitigation}</li>`
                        ).join('')}
                    </ul>
                </details>
            </div>
    `;

    return card;
}