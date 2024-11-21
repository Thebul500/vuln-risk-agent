require('dotenv').config();
const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const axios = require('axios');
const fetch = require('node-fetch');
const app = express();
app.use(express.json());

// Add CORS middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'http://localhost:8080');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

// Services
const threatModelingService = require('./services/threatModelingService');
const npmAuditService = require('./services/npmAuditService');
const vulnResearchService = require('./services/vulnResearchService');
const reportingService = require('./services/reportingService');

// Endpoint to trigger analysis
app.post('/analyze', async (req, res) => {

  const repoUrl = req.body.githubUrl;

  // Validate GitHub URL
  const githubUrlPattern = /^https?:\/\/github\.com\/[\w-]+\/[\w.-]+(?:\.git)?$/;
  if (!githubUrlPattern.test(repoUrl)) {
    return res.status(400).send('Invalid GitHub repository URL. Please provide a valid GitHub repository URL.');
  }

  // Clone the repository
  console.log(`Cloning repository ${repoUrl}...`);
  exec(`git clone ${repoUrl}`, async (err) => {
    if (err) return res.status(500).send('Repository cloning failed.');

    const projectDirName = repoUrl.split('/').pop().replace('.git', '');
    console.log("projectDirName: ", projectDirName);  

    // Run threat model and npm audit in parallel
    console.log("Starting threat modeling and NPM audit in parallel...");
    try {
      await Promise.all([
        threatModelingService.runThreatModeling(projectDirName)
          .then(() => console.log("Threat model generated and saved successfully"))
          .catch(error => {
            console.error("Error in threat modeling:", error);
            throw new Error('Threat modeling failed');
          }),
          
        npmAuditService.runAudit(projectDirName)
          .then(() => console.log("Finished npm audit."))
          .catch(error => {
            console.error("Error in NPM audit:", error);
            throw new Error('NPM audit failed');
          })
      ]);
    } catch (error) {
      return res.status(500).send(`Parallel execution failed: ${error.message}`);
    }
    
    // Vulnerability Research
    console.log("Starting vulnerability research...");
    try {
      await vulnResearchService.runResearch(projectDirName);
      console.log("Finished vulnerability research.");
    } catch (error) {
      console.error("Error in vulnerability research:", error);
      res.status(500).send('Error in vulnerability research');
    }

    // Reporting service
    console.log("Starting reporting service...");
    try {
      await reportingService.generateReport(projectDirName);
      console.log("Finished reporting service.");
    } catch (error) {
      console.error("Error in reporting service:", error);
      res.status(500).send('Error in reporting service');
    }

    // Return both the security assessment report and threat model
    try {
      const report = await fs.promises.readFile(`${projectDirName}/security-assessment-report.json`, 'utf8').catch(() => '{}');
      const threatModel = await fs.promises.readFile(`${projectDirName}/threat-model.md`, 'utf8').catch(() => '{}');
      
      res.json({
        vulnerabilities: JSON.parse(report),
        threatModel: threatModel
      });
      return;
    } catch (error) {
      console.error("Error reading assessment files:", error);
      res.status(500).send('Error reading assessment files');
    }
  });
});

app.listen(4000, () => {
  console.log('LLM agent running on port 4000');
});
