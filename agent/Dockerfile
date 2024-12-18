FROM node:20-alpine3.19
WORKDIR /app
COPY package*.json ./
RUN npm install
RUN apk add git   
COPY . .
CMD ["node", "agent.js"]
# Install required packages
