// Helper functions
function extractHighSeverityVulns(auditResults) {
    const highSeverityVulns = [];
    const vulnerabilities = auditResults.vulnerabilities || {};

    for (const [pkgName, vuln] of Object.entries(vulnerabilities)) {
        if (vuln.severity === 'high') {
            highSeverityVulns.push({
                packageName: pkgName,
                advisory: vuln.github_advisory_url,
                severity: vuln.severity,
                via: vuln.via,
                effects: vuln.effects,
                range: vuln.range,
                nodes: vuln.nodes
            });
        }
    }
    return highSeverityVulns;
}

async function researchVulnerabilities(vulns) {
const researchResults = [];

for (const vuln of vulns) {
    try {
    // Fetch advisory data from GitHub
    const advisoryData = await fetchGitHubAdvisory(vuln.advisory);
    
    const researchResult = {
        ...vuln,
        research: {
            description: advisoryData.description,
            attackVectors: advisoryData.attackVectors,
            impact: advisoryData.impact,
            exploitabilityAssessment: await assessExploitability(advisoryData, vuln)
        }
    };
    
        researchResults.push(researchResult);
    } catch (error) {
        console.error(`Error researching vulnerability for ${vuln.packageName}:`, error);
    }
}

return researchResults;
}

async function fetchGitHubAdvisory(advisoryUrl) {
// You'll need to implement GitHub API authentication
const githubToken = process.env.GITHUB_TOKEN;

try {
    const response = await axios.get(advisoryUrl, {
        headers: {
            'Authorization': `token ${githubToken}`,
            'Accept': 'application/vnd.github.v3+json'
        }
        });
        
        return {
        description: response.data.description,
        attackVectors: response.data.details,
        impact: response.data.severity,
        // Add other relevant fields from the GitHub Advisory API
        };
    } catch (error) {
        console.error('Error fetching GitHub advisory:', error);
        throw error;
    }
}

async function assessExploitability(advisoryData, vuln) {
    // This function will later integrate with your threat model
    // For now, return a basic assessment
    return {
        isExploitable: null, // Will be determined based on threat model
        reasoning: "Pending threat model integration",
        mitigationSteps: [],
        requiresAction: true
    };
}

module.exports = {
    extractHighSeverityVulns,
    researchVulnerabilities,
    fetchGitHubAdvisory,
    assessExploitability
};