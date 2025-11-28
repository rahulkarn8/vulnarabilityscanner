import { useState } from 'react'
import { Github, Mail, Lock } from 'lucide-react'
import axios from 'axios'
import { API_URL } from '../config'
import { useAuth } from '../contexts/AuthContext'
import './Login.css'

function Login() {
  const { login } = useAuth()
  const [isRegister, setIsRegister] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleGitHubLogin = () => {
    try {
      window.location.href = `${API_URL}/auth/github/login`
    } catch (error) {
      console.error('Error initiating GitHub login:', error)
      alert('Failed to initiate GitHub login. Please check your connection.')
    }
  }

  const handleGoogleLogin = () => {
    try {
      console.log('Initiating Google login, redirecting to:', `${API_URL}/auth/google/login`)
      window.location.href = `${API_URL}/auth/google/login`
    } catch (error) {
      console.error('Error initiating Google login:', error)
      alert('Failed to initiate Google login. Please check your connection.')
    }
  }

  const handleEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setLoading(true)

    try {
      if (isRegister) {
        // Register
        const response = await axios.post(`${API_URL}/auth/register`, {
          email,
          password,
          name
        })
        if (response.data.access_token) {
          login(response.data.access_token)
          // Reload to update auth state
          window.location.reload()
        }
      } else {
        // Login
        const response = await axios.post(`${API_URL}/auth/login`, {
          email,
          password
        })
        if (response.data.access_token) {
          login(response.data.access_token)
          // Reload to update auth state
          window.location.reload()
        }
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'An error occurred')
      setLoading(false)
    }
  }

  return (
    <div className="login-card">
      <div className="login-header">
        <h1>STRATUM</h1>
        <span className="tagline">by Daifend · AI CYBERSECURITY</span>
        <p className="login-subtitle">
          {isRegister ? 'Create an account' : 'Sign in to continue'}
        </p>
      </div>

      <div className="login-tabs">
        <button
          className={`login-tab ${!isRegister ? 'active' : ''}`}
          onClick={() => {
            setIsRegister(false)
            setError(null)
          }}
        >
          Login
        </button>
        <button
          className={`login-tab ${isRegister ? 'active' : ''}`}
          onClick={() => {
            setIsRegister(true)
            setError(null)
          }}
        >
          Register
        </button>
      </div>

      <form onSubmit={handleEmailSubmit} className="email-login-form">
        {isRegister && (
          <div className="form-group">
            <label htmlFor="name">Full Name</label>
            <input
              type="text"
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              disabled={loading}
              placeholder="Enter your name"
            />
          </div>
        )}
        <div className="form-group">
          <label htmlFor="email">Email</label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            disabled={loading}
            placeholder="Enter your email"
          />
        </div>
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            disabled={loading}
            placeholder={isRegister ? "At least 8 characters" : "Enter your password"}
            minLength={isRegister ? 8 : undefined}
          />
        </div>
        {error && (
          <div className="error-message">
            {error}
          </div>
        )}
        <button
          type="submit"
          className="email-submit-btn"
          disabled={loading}
        >
          {loading ? (
            <span>Processing...</span>
          ) : (
            <>
              <Lock size={18} />
              <span>{isRegister ? 'Create Account' : 'Sign In'}</span>
            </>
          )}
        </button>
      </form>

      <div className="login-divider">
        <span>OR</span>
      </div>

      <div className="login-options">
        <button onClick={handleGitHubLogin} className="login-btn github-btn">
          <Github size={18} />
          <span>Continue with GitHub</span>
        </button>
        <button onClick={handleGoogleLogin} className="login-btn google-btn">
          <Mail size={18} />
          <span>Continue with Google</span>
        </button>
      </div>
      <p className="login-footer">
        By continuing, you agree to our terms of service
      </p>
    </div>
  )
}

export default Login

