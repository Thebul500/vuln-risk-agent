const fs = require('fs').promises;
const path = require('path');
const { OpenAI } = require('openai');

class ThreatModelingService {
    constructor() {
        this.openai = new OpenAI({
            apiKey: process.env.OPENAI_API_KEY
        });
    }

    // Main method to run the threat modeling process
    async runThreatModeling(projectPath) {
        try {
            console.log('Starting threat modeling process for:', projectPath);
            
            // Step 1: Collect project metadata
            console.log('Collecting project metadata...');
            const metadata = await this.collectProjectMetadata(projectPath);
            
            // Step 2: Generate threat model
            console.log('Generating threat model...');
            const threatModel = await this.generateThreatModel(metadata);
            
            // Step 3: Save threat model
            console.log('Saving threat model...');
            await this.saveThreatModel(projectPath, threatModel);
            
            console.log('Threat modeling process completed successfully');
            return threatModel;
        } catch (error) {
            console.error('Error in threat modeling process:', error);
            throw error;
        }
    }

    async collectProjectMetadata(projectPath) {
        console.log("collectProjectMetadata: ", projectPath);
        const metadata = {};
        
        try {
            // Get README content
            console.log("Getting README content...");
            const readmePath = path.join(projectPath, 'README.md');
            metadata.readme = await fs.readFile(readmePath, 'utf8').catch(() => '');
            console.log("README content: ", metadata.readme);

            // Get package.json content
            console.log("Getting package.json content...");
            const packagePath = path.join(projectPath, 'package.json');
            metadata.packageJson = JSON.parse(
                await fs.readFile(packagePath, 'utf8').catch(() => '{}')
            );
            console.log("package.json content: ", metadata.packageJson);

            // Get directory structure
            console.log("Getting directory structure...");
            metadata.structure = await this.getDirectoryStructure(projectPath);
            console.log("directory structure: ", metadata.structure);

            // Get security-related files
            console.log("Getting security-related files...");
            metadata.securityConfig = await this.getSecurityRelatedFiles(projectPath);
            console.log("security-related files: ", metadata.securityConfig);

            // Get exposed ports from package.json scripts
            console.log("Getting exposed ports from package.json scripts...");
            metadata.exposedPorts = Object.values(metadata.packageJson.scripts || {})
                .join(' ')
                .match(/port\s*=?\s*(\d+)/gi) || [];
            console.log("exposedPorts: ", metadata.exposedPorts);

            console.log("Metadata collected successfully");
            return metadata;
        } catch (error) {
            console.error('Error collecting metadata:', error);
            throw error;
        }
    }

    // Get security-related files helper
    async getSecurityRelatedFiles(projectPath) {
        // Check for security-related files
        console.log("Checking for security-related files...");
        const securityFiles = ['dockerfile', 'docker-compose.yml', '.env.example', '.npmrc', '.gitlab-ci.yml', '.github/workflows'];
        const securityConfig = await Promise.all(
            securityFiles.map(async file => {
                const filePath = path.join(projectPath, file);
                try {
                    const exists = await fs.access(filePath).then(() => true);
                    if (!exists) return null;

                    const fileData = { name: file };

                    // Analyze specific files
                    switch (file.toLowerCase()) {
                        case 'dockerfile':
                            const dockerContent = await fs.readFile(filePath, 'utf8');
                            fileData.baseImage = dockerContent.match(/^FROM\s+([^\n]+)/m)?.[1];
                            fileData.exposedPorts = dockerContent.match(/EXPOSE\s+(\d+)/g)?.map(p => p.split(' ')[1]);
                            break;

                        case 'docker-compose.yml':
                            const composeContent = await fs.readFile(filePath, 'utf8');
                            fileData.services = composeContent.match(/^services:/m) ? true : false;
                            fileData.volumes = composeContent.match(/volumes:/g)?.length || 0;
                            break;

                        case '.env.example':
                            const envContent = await fs.readFile(filePath, 'utf8');
                            fileData.sensitiveVars = envContent.match(/(?:PASSWORD|SECRET|KEY|TOKEN)/gi)?.length || 0;
                            break;

                        case '.npmrc':
                            const npmrcContent = await fs.readFile(filePath, 'utf8');
                            fileData.hasRegistry = npmrcContent.includes('registry=');
                            fileData.hasToken = npmrcContent.includes('//registry.npmjs.org/:_authToken=');
                            break;

                        case '.gitlab-ci.yml':
                        case '.github/workflows':
                            const ciContent = await fs.readFile(filePath, 'utf8');
                            fileData.hasTests = ciContent.match(/\b(test|jest|mocha|cypress)\b/i) !== null;
                            fileData.hasSecurityScans = ciContent.match(/\b(snyk|sonar|dependency|security|audit)\b/i) !== null;
                            break;
                    }

                    return fileData;
                } catch {
                    return null;
                }
            })
        ).then(files => files.filter(Boolean));
        console.log("securityConfig: ", securityConfig);
        return securityConfig;
    }

    // Get directory structure helper
    async getDirectoryStructure(dirPath, depth = 2) {
        const items = await fs.readdir(dirPath);
        const structure = {};

        for (const item of items) {
            if (item.startsWith('.') || item === 'node_modules') continue;
            
            const fullPath = path.join(dirPath, item);
            const stats = await fs.stat(fullPath);

            if (stats.isDirectory() && depth > 0) {
                structure[item] = await this.getDirectoryStructure(fullPath, depth - 1);
            } else if (stats.isFile()) {
                structure[item] = 'file';
            }
        }

        return structure;
    }

    // Generate threat model helper
    async generateThreatModel(metadata) {
        const prompt = `
Your task is to analyze the following project metadata and create a threat model which will serve as context for assessing the risk of vulnerabilities identifies by an npm audit scan.
The threat model should offer context about the project which will be used by a security engineer to assess the impact of known vulnerabilities in the target project.
In later stage in this workflow, the npm audit scan will run on the project and it will be enriched with GitHub advisory data.
Then, the security engineer will assess the vulnerability data in the context of the threat model to determine the vulnerability's exploitability.

Here is the project metada:

README:
${metadata.readme}

Package.json:
${JSON.stringify(metadata.packageJson, null, 2)}

Directory Structure:
${JSON.stringify(metadata.structure, null, 2)}

Security-related files:
${JSON.stringify(metadata.securityConfig, null, 2)}

Exposed ports:
${metadata.exposedPorts.join(', ')}

Please analyze potential security threats and vulnerabilities, focusing on:
1. How common web vulnerabilities which are applicable to this project
2. Application-specific attack vectors
3. Required conditions for exploitation
4. Severity levels
5. Recommended mitigations

The threat model must include information which will help a security engineer to assess the risk of vulnerabilities in dependencies in the target project, such as:
- a summary of the project's purpose and architecture
- a list of all the project's dependencies (including devDependencies) and their purpose in the project
- a list of the project's exposed ports
- a list of the project's security-related files
- any other information which would help a security engineer to assess the risk of vulnerabilities in the target project;s dependencies`;

        try {
            const response = await this.openai.chat.completions.create({
                model: "o1-mini",
                messages: [{
                    "role": "user",
                    "content": prompt
                }]
            });

            return response.choices[0].message.content;
        } catch (error) {
            console.error('Error generating threat model:', error);
            throw error;
        }
    }

    // Save the threat model to a file
    async saveThreatModel(projectDirName, threatModel) {
        try {   
            await fs.writeFile(`${projectDirName}/threat-model.md`, threatModel);
            console.log("Threat model saved to file");
        } catch (error) {
            console.error('Error saving threat model:', error);
            throw new Error('Failed to save threat model');
        }
    }
}

module.exports = new ThreatModelingService();