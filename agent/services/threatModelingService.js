const fs = require('fs').promises;
const path = require('path');
const { OpenAI } = require('openai');

class ThreatModelingService {
    constructor() {
        this.openai = new OpenAI({
            apiKey: process.env.OPENAI_API_KEY
        });
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

            // Check for security-related files
            console.log("Checking for security-related files...");
            const securityFiles = ['dockerfile', 'docker-compose.yml', '.env.example', '.npmrc', '.gitlab-ci.yml', '.github/workflows'];
            metadata.securityConfig = await Promise.all(
                securityFiles.map(async file => {
                    const exists = await fs.access(path.join(projectPath, file))
                        .then(() => true)
                        .catch(() => false);
                    return exists ? file : null;
                })
            ).then(files => files.filter(Boolean));
            console.log("securityConfig: ", metadata.securityConfig);

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

    async generateThreatModel(metadata) {
        const prompt = `Based on the following project metadata, create a comprehensive threat model:

README:
${metadata.readme}

Package.json:
${JSON.stringify(metadata.packageJson, null, 2)}

Directory Structure:
${JSON.stringify(metadata.structure, null, 2)}

Please analyze potential security threats and vulnerabilities, focusing on:
1. Common web vulnerabilities applicable to this stack
2. Application-specific attack vectors
3. Required conditions for exploitation
4. Severity levels
5. Recommended mitigations`;

        try {
            const response = await this.openai.chat.completions.create({
                model: "gpt-3.5-turbo",
                messages: [{
                    role: "system",
                    content: "You are a security expert specialized in threat modeling."
                }, {
                    role: "user",
                    content: prompt
                }],
                temperature: 0.7,
                max_tokens: 2000
            });

            return response.choices[0].message.content;
        } catch (error) {
            console.error('Error generating threat model:', error);
            throw error;
        }
    }
}

module.exports = new ThreatModelingService();