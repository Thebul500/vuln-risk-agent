# Use Node.js official image as base
FROM node:20-alpine3.19

# Install required packages
RUN apk add git

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy application files
COPY . .

# Expose port 8080
EXPOSE 8080

# Start the application
CMD ["node", "index.js"]