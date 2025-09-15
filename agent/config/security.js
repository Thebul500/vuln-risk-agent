import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import dotenv from 'dotenv';

dotenv.config();

// Rate limiting configuration
export const rateLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: Math.ceil((parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000) / 1000)
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Too many requests from this IP, please try again later.',
      retryAfter: Math.ceil((parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000) / 1000)
    });
  }
});

// Helmet security configuration
export const helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.github.com", "https://api.openai.com"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});

// CORS configuration
export const corsOptions = {
  origin: process.env.CORS_ORIGIN || 'http://localhost:8080',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false,
  maxAge: 86400 // 24 hours
};

// Environment validation
export function validateEnvironment() {
  const required = ['GITHUB_TOKEN', 'OPENAI_API_KEY'];
  const missing = required.filter(key => !process.env[key]);

  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }

  // Validate GitHub token format
  if (!process.env.GITHUB_TOKEN.startsWith('ghp_') && !process.env.GITHUB_TOKEN.startsWith('github_pat_')) {
    console.warn('Warning: GitHub token format may be invalid');
  }

  // Validate OpenAI API key format
  if (!process.env.OPENAI_API_KEY.startsWith('sk-')) {
    console.warn('Warning: OpenAI API key format may be invalid');
  }
}