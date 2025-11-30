// API Configuration
// In development, use localhost. In production, use VITE_API_URL env var or backend Cloud Run URL
// Note: Frontend is on stratum.daifend.ai, but backend API is on Cloud Run URL (not custom domain)
const isDevelopment = import.meta.env.DEV || window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'

// Use VITE_API_URL if set (should be backend Cloud Run URL), otherwise use defaults
export const API_URL = import.meta.env.VITE_API_URL || (isDevelopment 
  ? 'http://localhost:8000' 
  : 'https://vulnerability-scanner-backend-oi4goiciua-ew.a.run.app' // Backend Cloud Run URL
)

