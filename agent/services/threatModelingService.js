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
                model: "o1-preview",
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