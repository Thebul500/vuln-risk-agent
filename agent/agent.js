import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import { exec } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import { generateReport } from './services/reportingService.js';
import { runThreatModeling } from './services/threatModelingService.js';
import npmAuditService from './services/npmAuditService.js';
import vulnResearchService from './services/vulnResearchService.js';
import { rateLimiter, helmetConfig, corsOptions, validateEnvironment } from './config/security.js';
import { logger, requestLogger, logAnalysis, logSecurityEvent } from './utils/logger.js';

dotenv.config();

// Validate environment variables on startup
try {
  validateEnvironment();
  logger.info('Environment validation passed');
} catch (error) {
  logger.error('Environment validation failed:', error);
  process.exit(1);
}

const app = express();

// Trust proxy if behind reverse proxy
if (process.env.TRUST_PROXY === 'true') {
  app.set('trust proxy', 1);
}

// Security middleware
app.use(helmetConfig);
app.use(cors(corsOptions));
app.use(rateLimiter);
app.use(express.json({ limit: '10mb' }));
app.use(requestLogger);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0'
  });
});

// API documentation endpoint
app.get('/api-docs', (req, res) => {
  res.json({
    endpoints: {
      'POST /analyze': 'Analyze a GitHub repository for vulnerabilities',
      'GET /health': 'Health check endpoint',
      'GET /api-docs': 'API documentation'
    },
    version: process.env.npm_package_version || '1.0.0'
  });
});

// Enhanced analysis endpoint with comprehensive error handling
app.post('/analyze', async (req, res) => {
  const startTime = Date.now();
  let projectDirName = null;

  try {
    logger.info('Analysis request received', { ip: req.ip, userAgent: req.get('User-Agent') });

    // Enhanced input validation
    const { githubUrl, options = {} } = req.body;

    if (!githubUrl) {
      logSecurityEvent('invalid_input', { reason: 'missing_github_url', ip: req.ip });
      return res.status(400).json({
        error: 'GitHub repository URL is required',
        code: 'MISSING_URL'
      });
    }

    const githubUrlPattern = /^https?:\/\/github\.com\/[\w.-]+\/[\w.-]+(?:\.git)?\/?$/;
    if (!githubUrlPattern.test(githubUrl)) {
      logSecurityEvent('invalid_input', { reason: 'invalid_github_url', url: githubUrl, ip: req.ip });
      return res.status(400).json({
        error: 'Invalid GitHub repository URL format',
        code: 'INVALID_URL_FORMAT',
        expected: 'https://github.com/owner/repository'
      });
    }

    logAnalysis('analysis_started', githubUrl, { options });

    // Enhanced repository cloning with timeout and validation
    projectDirName = githubUrl.split('/').pop().replace('.git', '').replace('/', '');
    const workspacePath = path.join(process.cwd(), 'analysis-workspace');

    // Ensure workspace directory exists
    await fs.mkdir(workspacePath, { recursive: true });

    const cloneTimeout = parseInt(process.env.CLONE_TIMEOUT_MS) || 60000;

    logger.info(`Cloning repository: ${githubUrl}`);

    await new Promise((resolve, reject) => {
      const cloneProcess = exec(
        `cd ${workspacePath} && git clone --depth 1 ${githubUrl} ${projectDirName}`,
        { timeout: cloneTimeout },
        (error, stdout, stderr) => {
          if (error) {
            logger.error('Repository cloning failed', { error: error.message, stderr });
            reject(new Error(`Failed to clone repository: ${error.message}`));
          } else {
            logger.info(`Repository cloned successfully: ${projectDirName}`);
            resolve(stdout);
          }
        }
      );

      cloneProcess.on('timeout', () => {
        reject(new Error('Repository cloning timed out'));
      });
    });

    // Validate that package.json exists (Node.js project)
    const packageJsonPath = path.join(workspacePath, projectDirName, 'package.json');
    try {
      await fs.access(packageJsonPath);
    } catch {
      throw new Error('This does not appear to be a Node.js project (no package.json found)');
    }

    // Enhanced parallel analysis with timeout
    logger.info('Starting comprehensive security analysis');

    const analysisTimeout = parseInt(process.env.ANALYSIS_TIMEOUT_MS) || 300000; // 5 minutes
    const projectPath = path.join(workspacePath, projectDirName);

    const analysisPromise = Promise.all([
      runThreatModeling(projectPath),
      npmAuditService.runAudit(projectPath)
    ]);

    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Analysis timeout')), analysisTimeout);
    });

    await Promise.race([analysisPromise, timeoutPromise]);
    logger.info('Threat modeling and NPM audit completed');

    // Enhanced vulnerability research
    logger.info('Starting vulnerability research');
    await vulnResearchService.runResearch(projectPath);
    logger.info('Vulnerability research completed');

    // Generate comprehensive security report
    logger.info('Generating final security assessment report');
    const reportPath = await generateReport(projectPath);

    // Read generated analysis files
    const [reportContent, threatModelContent] = await Promise.allSettled([
      fs.readFile(reportPath, 'utf8'),
      fs.readFile(path.join(projectPath, 'threat-model.md'), 'utf8')
    ]);

    const report = reportContent.status === 'fulfilled' ? JSON.parse(reportContent.value) : {};
    const threatModel = threatModelContent.status === 'fulfilled' ? threatModelContent.value : 'Threat model generation failed';

    const analysisTime = Date.now() - startTime;

    logAnalysis('analysis_completed', githubUrl, {
      analysisTime: `${analysisTime}ms`,
      vulnerabilityCount: Array.isArray(report.vulnerabilities) ? report.vulnerabilities.length : 0
    });

    // Send comprehensive response
    res.json({
      success: true,
      repository: githubUrl,
      analysisTime: `${analysisTime}ms`,
      timestamp: new Date().toISOString(),
      vulnerabilities: report,
      threatModel: threatModel,
      metadata: {
        analysisVersion: process.env.npm_package_version || '1.0.0',
        toolsUsed: ['npm-audit', 'github-advisories', 'threat-modeling', 'openai-analysis']
      }
    });

  } catch (error) {
    const analysisTime = Date.now() - startTime;
    logger.error('Analysis failed', {
      error: error.message,
      stack: error.stack,
      repository: req.body.githubUrl,
      analysisTime: `${analysisTime}ms`
    });

    logAnalysis('analysis_failed', req.body.githubUrl, {
      error: error.message,
      analysisTime: `${analysisTime}ms`
    });

    res.status(500).json({
      success: false,
      error: error.message,
      code: 'ANALYSIS_FAILED',
      analysisTime: `${analysisTime}ms`,
      timestamp: new Date().toISOString()
    });

  } finally {
    // Enhanced cleanup with error handling
    if (projectDirName) {
      try {
        const workspacePath = path.join(process.cwd(), 'analysis-workspace');
        const projectPath = path.join(workspacePath, projectDirName);
        await fs.rm(projectPath, { recursive: true, force: true });
        logger.info(`Cleaned up analysis workspace: ${projectDirName}`);
      } catch (cleanupError) {
        logger.error('Cleanup failed', { error: cleanupError.message, projectDirName });
      }
    }
  }
});

// Global error handler
app.use((error, req, res, next) => {
  logger.error('Unhandled error', {
    error: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method
  });

  res.status(500).json({
    success: false,
    error: 'Internal server error',
    code: 'INTERNAL_ERROR',
    timestamp: new Date().toISOString()
  });
});

// Handle 404s
app.use((req, res) => {
  logSecurityEvent('endpoint_not_found', { url: req.url, method: req.method, ip: req.ip });
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    code: 'NOT_FOUND',
    availableEndpoints: ['/analyze', '/health', '/api-docs']
  });
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  logger.info(`Vuln Risk Agent server started`, {
    port: PORT,
    environment: process.env.NODE_ENV || 'development',
    version: process.env.npm_package_version || '1.0.0'
  });
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', { reason, promise });
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', { error: error.message, stack: error.stack });
  process.exit(1);
});
