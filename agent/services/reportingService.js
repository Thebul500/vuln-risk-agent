import fs from 'fs/promises';
import path from 'path';
import { OpenAI } from 'openai';

class ReportingService {
  constructor() {
    this.openai = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY
    });
  }

  async generateReport(projectPath) {
    try {
      console.log('Generating security assessment report...');

      // Read threat model and vulnerabilities
      const threatModelPath = path.join(projectPath, 'threat-model.md');
      const threatModel = await fs.readFile(threatModelPath, 'utf8').catch(() => 'Threat model not available.');

      const vulnerabilitiesPath = path.join(projectPath, 'npm-audit-report.json');
      const vulnerabilities = await fs.readFile(vulnerabilitiesPath, 'utf8').catch(() => '{}');

      // Generate report content using OpenAI
      const reportContent = await this.createReport(threatModel, JSON.parse(vulnerabilities));
      const reportPath = path.join(projectPath, 'security-assessment-report.json');

      // Save the report to a file
      await fs.writeFile(reportPath, JSON.stringify(reportContent, null, 2), 'utf8');
      console.log('Security assessment report saved at:', reportPath);

      return reportPath;
    } catch (error) {
      console.error('Error generating security assessment report:', error);
      throw error;
    }
  }

  async createReport(threatModel, vulnerabilities) {
    try {
      console.log('Creating report with OpenAI...');
      const reportPrompt = `
        Generate a security assessment report:
        - Threat Model:
        ${threatModel}

        - Vulnerabilities:
        ${JSON.stringify(vulnerabilities)}
      `;

      const response = await this.openai.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'system', content: reportPrompt }]
      });

      return response.choices[0].message.content;
    } catch (error) {
      console.error('Error creating report with OpenAI:', error);
      throw error;
    }
  }
}

// Named export
export const generateReport = (projectPath) => {
  const service = new ReportingService();
  return service.generateReport(projectPath);
};
