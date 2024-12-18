import { OpenAI } from 'openai';
import fs from 'fs/promises';
import path from 'path';

class ThreatModelingService {
    constructor() {
        this.openai = new OpenAI({
            apiKey: process.env.OPENAI_API_KEY,
        });
    }

    // Main method to run the threat modeling process
    async runThreatModeling(projectPath) {
        try {
            console.log('Starting threat modeling process for:', projectPath);

            // Step 1: Collect project metadata
            const metadata = await this.collectProjectMetadata(projectPath);

            // Step 2: Generate threat model
            const threatModel = await this.generateThreatModel(metadata);

            // Step 3: Save threat model
            await this.saveThreatModel(projectPath, threatModel);

            console.log('Threat modeling process completed successfully');
            return threatModel;
        } catch (error) {
            console.error('Error in threat modeling process:', error);
            throw error;
        }
    }

    async collectProjectMetadata(projectPath) {
        const metadata = {};
        try {
            // Collect README content
            const readmePath = path.join(projectPath, 'README.md');
            metadata.readme = await fs.readFile(readmePath, 'utf8').catch(() => '');
            
            // Collect package.json content
            const packagePath = path.join(projectPath, 'package.json');
            metadata.packageJson = JSON.parse(
                await fs.readFile(packagePath, 'utf8').catch(() => '{}')
            );

            // Collect directory structure
            metadata.structure = await this.getDirectoryStructure(projectPath);

            // Collect security-related files
            metadata.securityConfig = await this.getSecurityRelatedFiles(projectPath);

            // Collect exposed ports from package.json scripts
            metadata.exposedPorts = Object.values(metadata.packageJson.scripts || {})
                .join(' ')
                .match(/port\s*=?\s*(\d+)/gi) || [];

            return metadata;
        } catch (error) {
            console.error('Error collecting metadata:', error);
            throw error;
        }
    }

    async getSecurityRelatedFiles(projectPath) {
        const securityFiles = ['dockerfile', 'docker-compose.yml', '.env.example', '.npmrc', '.gitlab-ci.yml', '.github/workflows'];
        const results = await Promise.all(
            securityFiles.map(async (file) => {
                const filePath = path.join(projectPath, file);
                try {
                    await fs.access(filePath);
                    const fileData = { name: file };

                    switch (file.toLowerCase()) {
                        case 'dockerfile':
                            const dockerContent = await fs.readFile(filePath, 'utf8');
                            fileData.baseImage = dockerContent.match(/^FROM\s+([^\n]+)/m)?.[1];
                            fileData.exposedPorts = dockerContent.match(/EXPOSE\s+(\d+)/g)?.map((p) => p.split(' ')[1]);
                            break;
                        case 'docker-compose.yml':
                            const composeContent = await fs.readFile(filePath, 'utf8');
                            fileData.services = composeContent.includes('services:');
                            fileData.volumes = (composeContent.match(/volumes:/g) || []).length;
                            break;
                        case '.env.example':
                            const envContent = await fs.readFile(filePath, 'utf8');
                            fileData.sensitiveVars = (envContent.match(/(?:PASSWORD|SECRET|KEY|TOKEN)/gi) || []).length;
                            break;
                        case '.npmrc':
                            const npmrcContent = await fs.readFile(filePath, 'utf8');
                            fileData.hasRegistry = npmrcContent.includes('registry=');
                            fileData.hasToken = npmrcContent.includes('//registry.npmjs.org/:_authToken=');
                            break;
                        case '.gitlab-ci.yml':
                        case '.github/workflows':
                            const ciContent = await fs.readFile(filePath, 'utf8');
                            fileData.hasTests = /\b(test|jest|mocha|cypress)\b/i.test(ciContent);
                            fileData.hasSecurity = ciContent.includes('SECURITY');
                            break;
                    }
                    return fileData;
                } catch {
                    return null;
                }
            })
        );
        return results.filter(Boolean);
    }

    async getDirectoryStructure(projectPath) {
        try {
            return await fs.readdir(projectPath);
        } catch (error) {
            console.error('Error reading directory structure:', error);
            return [];
        }
    }

    async generateThreatModel(metadata) {
        try {
            const prompt = `
                Threat Model: 
                Analyze the following project metadata and identify potential threats and mitigations:
                Metadata: ${JSON.stringify(metadata)}
            `;
            const response = await this.openai.chat.completions.create({
                model: 'gpt-4',
                messages: [{ role: 'system', content: prompt }],
            });
            return response.choices[0]?.message?.content || 'No threat model generated.';
        } catch (error) {
            console.error('Error generating threat model:', error);
            throw error;
        }
    }

    async saveThreatModel(projectPath, threatModel) {
        const filePath = path.join(projectPath, 'threat-model.md');
        try {
            await fs.writeFile(filePath, threatModel, 'utf8');
            console.log('Threat model saved to:', filePath);
        } catch (error) {
            console.error('Error saving threat model:', error);
            throw error;
        }
    }
}

// Named export for use in other files
export const runThreatModeling = (projectPath) => {
    const service = new ThreatModelingService();
    return service.runThreatModeling(projectPath);
};
