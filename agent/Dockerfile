FROM node:20-alpine3.19
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
CMD ["node", "agent.js"]
# Install required packages
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*