#!/bin/bash
git clone $1 target-project
cd target-project
npm audit --json > audit-report.json
