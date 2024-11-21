require('dotenv').config();
const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const axios = require('axios');
const fetch = require('node-fetch');
const app = express();
app.use(express.json());

// Services
const threatModelingService = require('./services/threatModelingService');
const npmAuditService = require('../services/npmAuditService');

// Endpoint to trigger analysis
app.post('/analyze', async (req, res) => {
  const repoUrl = req.body.repoUrl;

  // Clone the repository
  console.log(`Cloning repository ${repoUrl}...`);
  exec(`git clone ${repoUrl}`, async (err) => {
    if (err) return res.status(500).send('Repository cloning failed.');

    const projectDirName = repoUrl.split('/').pop().replace('.git', '');
    console.log("projectDirName: ", projectDirName);

    // Threat Modeling
    try {
      const metadata = await threatModelingService.collectProjectMetadata(projectDirName);
      console.log("metadata: ", metadata);
    } catch (error) {
      console.error("Error in threat modeling:", error);
      res.status(500).send('Error in threat modeling');
    }

    // NPM Audit
    try {
      const auditResults = await npmAuditService.performAudit(projectDirName);
      console.log("auditResults: ", auditResults);
    } catch (error) {
      console.error("Error in NPM audit:", error);
      res.status(500).send('Error in NPM audit');
    }
    
    // Vulnerability Research

    // Reporting and Visualization
    
  });
});

app.listen(4000, () => {
  console.log('Multi-Agent System running on port 4000');
});
