// API Configuration
// In development, use localhost. In production, use the domain or VITE_API_URL env var
const isDevelopment = import.meta.env.DEV || window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
export const API_URL = import.meta.env.VITE_API_URL || (isDevelopment ? 'http://localhost:8000' : 'https://stratum.daifend.ai')

