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
const npmAuditService = require('./services/npmAuditService');
const vulnResearchService = require('./services/vulnResearchService');

// Endpoint to trigger analysis
app.post('/analyze', async (req, res) => {
  const repoUrl = req.body.repoUrl;
  
  // Clone the repository
  console.log(`Cloning repository ${repoUrl}...`);
  exec(`git clone ${repoUrl}`, async (err) => {
    if (err) return res.status(500).send('Repository cloning failed.');

    const projectDirName = repoUrl.split('/').pop().replace('.git', '');
    console.log("projectDirName: ", projectDirName);  
    
    // Threat Modeling Service
    console.log("Starting threat modeling...");
    try {
      const metadata = await threatModelingService.collectProjectMetadata(projectDirName);
      console.log("metadata: ", metadata);

      console.log("Generating threat model...");
      const threatModel = await threatModelingService.generateThreatModel(metadata);
      console.log("threatModel: ", threatModel);

      console.log("Saving threat model to file...");
      await threatModelingService.saveThreatModel(projectDirName, threatModel);
      console.log("Threat model saved to file");

    } catch (error) {
      console.error("Error in threat modeling:", error);
      res.status(500).send('Error in threat modeling');
    }

    // NPM Audit Service
    console.log("Starting NPM audit...");
    try {
      await npmAuditService.runAudit(projectDirName);
      console.log("Finished npm audit.");
    } catch (error) {
      console.error("Error in NPM audit:", error);
      res.status(500).send('Error in NPM audit');
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

    // Reporting and Visualization

  });
});

app.listen(4000, () => {
  console.log('LLM agent running on port 4000');
});
