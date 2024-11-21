require('dotenv').config();
const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const axios = require('axios');
const fetch = require('node-fetch');
const app = express();
app.use(express.json());

// Endpoint to trigger analysis
app.post('/analyze', async (req, res) => {
  const repoUrl = req.body.repoUrl;
//   const projectPath = '/app/target-project';
//   console.log("projectPath: ", projectPath);

  // Clone the repository
  console.log(`Cloning repository ${repoUrl}...`);
  exec(`git clone ${repoUrl}`, (err) => {
    if (err) return res.status(500).send('Repository cloning failed.');

    const projectDirName = repoUrl.split('/').pop().replace('.git', '');
    console.log("projectDirName: ", projectDirName);

    // First run npm install with --force
    console.log(`Starting npm install for ${projectDirName}...`);
    exec(`cd ${projectDirName} && npm install --force`, (installErr, installStdout, installStderr) => {
      if (installErr) {
        console.error('npm install error:', installErr);
        console.error('install stderr:', installStderr);
        return res.status(500).send('npm install failed.');
      }

      // Then run npm audit separately
      console.log(`Starting npm audit for ${projectDirName}...`);
      exec(`cd ${projectDirName} && npm audit --json`, async (auditErr, stdout, stderr) => {
        let auditResults;
        try {
          // Even if audit has high severity issues, it will return JSON
          auditResults = JSON.parse(stdout);
          console.log("auditResults: ", auditResults);
        } catch (parseErr) {
          console.error('Failed to parse audit results:', parseErr);
          console.log('Raw stdout:', stdout);
          return res.status(500).send('Failed to parse audit results.');
        }

        // Write audit results to a file
        console.log(`Writing audit results to ${projectDirName}/npm-audit-results.json...`);
        try {
          await fs.promises.writeFile(
            `${projectDirName}/npm-audit-results.json`,
            JSON.stringify(auditResults, null, 2)
          );
          console.log("auditResults written to file");
        } catch (writeErr) {
          console.error('Failed to write audit results:', writeErr);
          return res.status(500).send('Failed to save audit results.');
        }

        res.json(auditResults)
      });
    });
  });
});

app.listen(4000, () => {
  console.log('Multi-Agent System running on port 4000');
});
