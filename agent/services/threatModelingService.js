import { OpenAI } from 'openai';
import fs from 'fs/promises';
import path from 'path';

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
                            fileData.hasSecurity = ciContent.includes('SECURITY');
                            break;
                    }
                    return fileData;
                } catch (error) {
                    console.log(`Error accessing file ${file}:`, error);
                    return null;
                }
            })
        );
        return securityConfig.filter(file => file);
    }

    async getDirectoryStructure(projectPath) {
        console.log("Scanning directory structure...");
        const items = await fs.readdir(projectPath);
        return items;
    }

    async generateThreatModel(metadata) {
        // Generate the threat model using OpenAI
        console.log("Generating threat model from metadata...");
        const threatModelPrompt = `
            Threat Model: 
            This is the threat model based on the metadata provided:
            Project Metadata: ${JSON.stringify(metadata)}
        `;
        
        const modelResponse = await this.openai.chat.completions.create({
            model: 'gpt-4',
            messages: [{ role: 'system', content: threatModelPrompt }]
        });

        return modelResponse.choices[0].message.content;
    }

    async saveThreatModel(projectPath, threatModel) {
        const filePath = path.join(projectPath, 'threat-model.md');
        await fs.writeFile(filePath, threatModel, 'utf8');
        console.log("Threat model saved to:", filePath);
    }
}

// Named export
export const runThreatModeling = (projectPath) => {
    const service = new ThreatModelingService();
    return service.runThreatModeling(projectPath);
};
