const fs = require('fs').promises;
const path = require('path');
const { OpenAI } = require('openai');

class ReportingService {
    constructor() {
        this.openai = new OpenAI({
            apiKey: process.env.OPENAI_API_KEY
        });
    }

    async generateReport(projectDirName) {
        try {
            // Load all the data sources
            console.log("Loading data sources...");
            const threatModel = await fs.readFile(
                path.join(projectDirName, 'threat-model.md'), 
                'utf8'
            );
            
            const vulnResearch = JSON.parse(await fs.readFile(
                path.join(projectDirName, 'vuln-research-results.json'),
                'utf8'
            ));

            const npmAudit = JSON.parse(await fs.readFile(
                path.join(projectDirName, 'npm-audit-results.json'),
                'utf8'
            ));

            // Generate exploitability assessment
            console.log("Assessing exploitability...");
            const report = await this.assessExploitability(threatModel, vulnResearch, npmAudit);
            
            // Save the report
            console.log("Saving report...");
            await this.saveReport(projectDirName, report);
            
            return report;
        } catch (error) {
            console.error('Error generating security report:', error);
            throw error;
        }
    }

    async assessExploitability(threatModel, vulnResearch, npmAudit) {
        // Filter for high/critical severity vulnerabilities
        const highSeverityVulns = vulnResearch.filter(vuln => 
            vuln.severity === 'high' || vuln.severity === 'critical'
        );

        const prompt = `
You are a security engineer assessing the exploitability of vulnerabilities in the context of a threat model.
Your task is to analyze each high/critical severity vulnerability and determine if it's exploitable in this specific project context.

Threat Model:
${threatModel}

For each of the following vulnerabilities, assess:
1. Is the vulnerability exploitable in this project's context? Why or why not?
2. What specific conditions would be required for exploitation?
3. How does the threat model's context influence the risk level?
4. What specific mitigations would you recommend?

Vulnerabilities to assess:
${JSON.stringify(highSeverityVulns, null, 2)}

NPM Audit Additional Context:
${JSON.stringify(npmAudit.vulnerabilities, null, 2)}

Provide your assessment as a JSON array where each item follows this structure:
[
    {
        "packageName": "package-name",
        "vulnerability": {
            "summary": "Brief description",
            "isExploitable": true/false,
            "exploitabilityReasoning": "Detailed explanation",
            "requiredConditions": ["condition1", "condition2"],
            "contextualRiskLevel": "high/medium/low",
            "recommendedMitigations": ["mitigation1", "mitigation2"]
        }
    }
]

Return only the JSON array with no additional text or formatting.`;
        try {
            console.log("Assessing exploitability with OpenAI...");
            const response = await this.openai.chat.completions.create({
                model: "o1-preview",
                messages: [{
                    "role": "user",
                    "content": prompt
                }]
            });

            return response.choices[0].message.content;
        } catch (error) {
            console.error('Error assessing exploitability:', error);
            throw error;
        }
    }

    async saveReport(projectDirName, report) {
        try {
            console.log("Saving report...");
            await fs.writeFile(
                path.join(projectDirName, 'security-assessment-report.json'),
                typeof report === 'string' ? report : JSON.stringify(report, null, 2)
            );
            console.log("Security assessment report saved to file");
        } catch (error) {
            console.error('Error saving security report:', error);
            throw new Error('Failed to save security report');
        }
    }
}

module.exports = new ReportingService();