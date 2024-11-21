const { exec } = require('child_process');
const fs = require('fs').promises;

class NpmAuditService {
  async runAudit(projectDirName) {
    try {
      // First run npm install with --force
      await this.runNpmInstall(projectDirName);
      
      // Then run npm audit
      const auditResults = await this.performAudit(projectDirName);
      
      // Save audit results
      await this.saveAuditResults(projectDirName, auditResults);
      
      return auditResults;
    } catch (error) {
      throw new Error(`Audit process failed: ${error.message}`);
    }
  }

  runNpmInstall(projectDirName) {
    return new Promise((resolve, reject) => {
      exec(`cd ${projectDirName} && npm install --force`, (error, stdout, stderr) => {
        if (error) {
          console.error('npm install error:', error);
          console.error('install stderr:', stderr);
          reject(new Error('npm install failed'));
        }
        resolve(stdout);
      });
    });
  }

  performAudit(projectDirName) {
    return new Promise((resolve, reject) => {
      exec(`cd ${projectDirName} && npm audit --json`, (error, stdout, stderr) => {
        try {
          const auditResults = JSON.parse(stdout);
          resolve(auditResults);
        } catch (parseError) {
          console.error('Failed to parse audit results:', parseError);
          console.log('Raw stdout:', stdout);
          reject(new Error('Failed to parse audit results'));
        }
      });
    });
  }

  async saveAuditResults(projectDirName, auditResults) {
    try {
      await fs.writeFile(
        `${projectDirName}/npm-audit-results.json`,
        JSON.stringify(auditResults, null, 2)
      );
      console.log("Audit results written to file");
    } catch (error) {
      throw new Error('Failed to save audit results');
    }
  }
}

module.exports = new NpmAuditService();