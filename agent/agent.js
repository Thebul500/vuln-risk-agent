import dotenv from 'dotenv';
import express from 'express';
import { exec } from 'child_process';
import fs from 'fs/promises';
import { generateReport } from './services/reportingService.js';  // Named import
import { runThreatModeling } from './services/threatModelingService.js';// Default import
import npmAuditService from './services/npmAuditService.js';  // Default import
import vulnResearchService from './services/vulnResearchService.js';  // Default import

dotenv.config();

const app = express();
app.use(express.json());

// Add CORS middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'http://localhost:8080');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

// Endpoint to trigger analysis
app.post('/analyze', async (req, res) => {
  console.log('Received request to analyze repository.');

  // Validate GitHub URL
  const repoUrl = req.body.githubUrl;
  const githubUrlPattern = /^https?:\/\/github\.com\/[\w-]+\/[\w.-]+(?:\.git)?$/;
  if (!githubUrlPattern.test(repoUrl)) {
    return res.status(400).send('Invalid GitHub repository URL. Please provide a valid URL.');
  }

  // Clone the repository
  const projectDirName = repoUrl.split('/').pop().replace('.git', '');
  console.log(`Cloning repository ${repoUrl}...`);
  try {
    await new Promise((resolve, reject) => {
      exec(`git clone ${repoUrl}`, (error) => {
        if (error) reject(error);
        else resolve();
      });
    });
    console.log(`Repository cloned to ${projectDirName}.`);
  } catch (error) {
    console.error('Error cloning repository:', error);
    return res.status(500).send('Repository cloning failed.');
  }

  // Run threat modeling and npm audit in parallel
  console.log('Starting threat modeling and NPM audit in parallel...');
  try {
    await Promise.all([
      threatModelingService.runThreatModeling(projectDirName),
      npmAuditService.runAudit(projectDirName)
    ]);
    console.log('Threat modeling and NPM audit completed.');
  } catch (error) {
    console.error('Error during parallel analysis:', error);
    return res.status(500).send('Error during analysis.');
  }

  // Vulnerability Research
  console.log('Starting vulnerability research...');
  try {
    await vulnResearchService.runResearch(projectDirName);
    console.log('Vulnerability research completed.');
  } catch (error) {
    console.error('Error in vulnerability research:', error);
    return res.status(500).send('Error in vulnerability research.');
  }

  // Generate the final report
  console.log('Generating the final security assessment report...');
  try {
    const reportPath = await generateReport(projectDirName);
    console.log('Security assessment report generated successfully.');

    // Read the generated files
    const report = await fs.readFile(reportPath, 'utf8');
    const threatModel = await fs.readFile(`${projectDirName}/threat-model.md`, 'utf8').catch(() => '{}');

    // Send the response
    res.json({
      vulnerabilities: JSON.parse(report),
      threatModel: threatModel
    });
  } catch (error) {
    console.error('Error generating final report:', error);
    res.status(500).send('Error generating final report.');
  } finally {
    // Clean up the cloned repository
    try {
      await fs.rm(projectDirName, { recursive: true, force: true });
      console.log(`Cleaned up cloned repository: ${projectDirName}`);
    } catch (cleanupError) {
      console.error('Error cleaning up cloned repository:', cleanupError);
    }
  }
});

app.listen(4000, () => {
  console.log('LLM agent running on port 4000.');
});
