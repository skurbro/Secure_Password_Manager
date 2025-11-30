# Multi-stage Dockerfile for Secure Password Manager
# Stage 1: Build Stage
FROM node:20-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY frontend/package*.json ./frontend/

# Install dependencies (including dev dependencies for build)
# Use npm install if package-lock.json is not available, otherwise npm ci is preferred
RUN npm install --ignore-scripts && \
    npm rebuild && \
    cd frontend && \
    npm install --ignore-scripts && \
    npm rebuild

# Copy source files (to avoid security hotspot with COPY . .)
COPY src ./src
COPY frontend ./frontend
COPY tsconfig.json ./

# Build the application
# This compiles TypeScript and builds React frontend
RUN npm run build:prod

# Stage 2: Production Stage (Runtime)
FROM node:20-alpine AS production

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create non-root user for security
# Use dynamic UID (Alpine will assign the next available)
RUN addgroup -S appgroup && \
    adduser -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm install --only=production --ignore-scripts && \
    npm rebuild && \
    npm cache clean --force

# Copy built application from builder stage
COPY --from=builder /app/dist ./dist

# Create directories for data and logs with proper permissions
RUN mkdir -p /app/.vault /app/logs && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the server
CMD ["node", "dist/web/server.js"]
