#!/bin/bash
# Usage: ./run-audit.sh <repository_url>

REPO_URL=$1
PROJECT_PATH="/app/target-project"

# Clone the repository
git clone $REPO_URL $PROJECT_PATH

# Navigate to the project directory
cd $PROJECT_PATH

# Run npm audit and save the report
npm audit --json > audit-report.json