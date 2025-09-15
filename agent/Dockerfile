# Multi-stage build for production optimization
FROM node:20-alpine AS builder

# Security: Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodeuser -u 1001 -G nodejs

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (including dev dependencies for build)
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY . .

# Change ownership to non-root user
RUN chown -R nodeuser:nodejs /app

# Production stage
FROM node:20-alpine AS production

# Security labels
LABEL maintainer="security@bul-network.com"
LABEL version="1.0.0"
LABEL description="Vuln Risk Agent - AI-powered vulnerability assessment"

# Install security updates and required tools
RUN apk update && \
    apk add --no-cache \
    git \
    curl \
    dumb-init \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodeuser -u 1001 -G nodejs

# Set working directory
WORKDIR /app

# Create necessary directories
RUN mkdir -p logs analysis-workspace && \
    chown -R nodeuser:nodejs /app

# Copy built application from builder stage
COPY --from=builder --chown=nodeuser:nodejs /app .

# Switch to non-root user
USER nodeuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-4000}/health || exit 1

# Expose port
EXPOSE 4000

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["npm", "start"]
