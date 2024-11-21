const axios = require('axios');
const fs = require('fs').promises;

class VulnResearchService {
    constructor() {
        this.githubToken = process.env.GITHUB_TOKEN;
    }

    // Main method to run the research process
    async runResearch(projectDirName) {
        try {
            // Read the audit results file
            const auditResultsFilePath = `${projectDirName}/npm-audit-results.json`;
            const auditResults = JSON.parse(await fs.readFile(auditResultsFilePath, 'utf8'));

            console.log("Extracting high severity vulnerabilities...");
            const highSeverityVulns = await this.extractHighSeverityVulns(auditResults);
            console.log("highSeverityVulns: ", highSeverityVulns);
            
            console.log("Researching vulnerabilities...");
            const researchResults = await this.researchVulnerabilities(highSeverityVulns);
            console.log("researchResults: ", researchResults);
            
            console.log("Saving research results...");
            await this.saveResearchResults(projectDirName, researchResults);
            console.log("Saved research results.");
            
            return researchResults;
        } catch (error) {
            throw new Error(`Vulnerability research failed: ${error.message}`);
        }
    }

    // Extract high severity vulnerabilities from the audit results
    async extractHighSeverityVulns(auditResults) {
        const highSeverityVulns = [];
        const vulnerabilities = auditResults.vulnerabilities || {};

        for (const [pkgName, vuln] of Object.entries(vulnerabilities)) {
            if (vuln.severity === 'high') {
                // Find GitHub advisory URL if it exists in the 'via' array
                let githubAdvisoryUrl = null;
                if (Array.isArray(vuln.via)) {
                    const advisoryObject = vuln.via.find(v => typeof v === 'object' && v.url);
                    if (advisoryObject) {
                        githubAdvisoryUrl = advisoryObject.url;
                    }
                }
                
                highSeverityVulns.push({
                    packageName: pkgName,
                    advisory: githubAdvisoryUrl,
                    severity: vuln.severity,
                    via: vuln.via,
                    effects: vuln.effects,
                    range: vuln.range,
                    nodes: vuln.nodes,
                    title: Array.isArray(vuln.via) ? 
                        vuln.via.find(v => typeof v === 'object' && v.title)?.title : null,
                    cwe: Array.isArray(vuln.via) ? 
                        vuln.via.find(v => typeof v === 'object' && v.cwe)?.cwe : null
                });
            }
        }
        return highSeverityVulns;
    }

    // Research vulnerabilities
    async researchVulnerabilities(vulns) {
        const researchResults = [];

        for (const vuln of vulns) {
            try {
                let advisoryData = {
                    description: 'No advisory data available',
                    attackVectors: [],
                    impact: vuln.severity
                };

                // Only fetch advisory data if advisory URL exists
                if (vuln.advisory) {
                    advisoryData = await this.fetchGitHubAdvisory(vuln.advisory);
                }
                
                const researchResult = {
                    ...vuln,
                    research: {
                        description: advisoryData.description,
                        attackVectors: advisoryData.attackVectors,
                        impact: advisoryData.impact,
                        exploitabilityAssessment: await this.assessExploitability(advisoryData, vuln)
                    }
                };
            
                researchResults.push(researchResult);
            } catch (error) {
                console.error(`Error researching vulnerability for ${vuln.packageName}:`, error);
                // Still add the vulnerability to results, but with error information
                researchResults.push({
                    ...vuln,
                    research: {
                        description: 'Error fetching advisory data',
                        error: error.message,
                        impact: vuln.severity,
                        exploitabilityAssessment: await this.assessExploitability({}, vuln)
                    }
                });
            }
        }

        return researchResults;
    }

    // Fetch advisory data from GitHub
    async fetchGitHubAdvisory(advisoryUrl) {
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

    // Assess exploitability
    async assessExploitability(advisoryData, vuln) {
        // This function will later integrate with your threat model
        // For now, return a basic assessment
        return {
            isExploitable: null, // Will be determined based on threat model
            reasoning: "Pending threat model integration",
            mitigationSteps: [],
            requiresAction: true
        };
    }

    async saveResearchResults(projectDirName, researchResults) {
        try {
            await fs.writeFile(
                `${projectDirName}/vuln-research-results.json`,
                JSON.stringify(researchResults, null, 2)
            );
            console.log("Research results written to file");
        } catch (error) {
            throw new Error('Failed to save research results');
        }
    }
}


module.exports = new VulnResearchService();