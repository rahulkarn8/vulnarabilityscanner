import { useState } from 'react'
import { X, Github, Mail, Lock, CreditCard } from 'lucide-react'
import axios from 'axios'
import { API_URL } from '../config'
import { useAuth } from '../contexts/AuthContext'
import './LoginPopup.css'

interface LoginPopupProps {
  isOpen: boolean
  onClose: () => void
  scansUsed?: number
  scanLimit?: number
}

function LoginPopup({ isOpen, onClose, scansUsed = 0, scanLimit = 5 }: LoginPopupProps) {
  const { login, isAuthenticated, token } = useAuth()
  const [isRegister, setIsRegister] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [loading, setLoading] = useState(false)
  const [checkoutLoading, setCheckoutLoading] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showPricing, setShowPricing] = useState(false)

  if (!isOpen) return null

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

  const handleViewPricing = () => {
    setShowPricing(true)
  }

  const handleCheckout = async (planId: string) => {
    // Check if user is authenticated
    if (!isAuthenticated || !token) {
      setError('Please log in to subscribe to a plan')
      setShowPricing(false) // Show login form
      return
    }

    setCheckoutLoading(planId)
    setError(null)

    try {
      // Create checkout session on backend
      const response = await axios.post(`${API_URL}/payment/create-checkout-session`, {
        plan_id: planId,
        success_url: `${window.location.origin}/?success=true`,
        cancel_url: `${window.location.origin}/?canceled=true`
      }, {
        headers: { Authorization: `Bearer ${token}` }
      })

      // Redirect to Stripe Checkout
      if (response.data.session_url) {
        window.location.href = response.data.session_url
      } else {
        throw new Error('No checkout URL received')
      }
    } catch (err: any) {
      console.error('Checkout error:', err)
      setError(err.response?.data?.detail || err.message || 'Failed to initiate checkout')
      setCheckoutLoading(null)
    }
  }

  return (
    <div className="login-popup-overlay" onClick={onClose}>
      <div className="login-popup-content" onClick={(e) => e.stopPropagation()}>
        <button className="login-popup-close" onClick={onClose}>
          <X size={20} />
        </button>

        {isAuthenticated || showPricing ? (
          <div className="login-popup-pricing">
            <h2>{isAuthenticated ? 'Subscribe to Continue Scanning' : 'Pricing Plans'}</h2>
            <p className="login-popup-subtitle" style={{ marginBottom: '24px', textAlign: 'center' }}>
              {isAuthenticated 
                ? `You've used ${scansUsed} of ${scanLimit} free scans. Choose a plan to get unlimited scanning.`
                : `You've used ${scansUsed} of ${scanLimit} free scans. Sign in and subscribe to continue scanning.`
              }
            </p>
            <div className="pricing-plans-grid">
              <div className="pricing-plan-card">
                <h3>Basic Plan</h3>
                <div className="plan-price">
                  <span className="currency">$</span>
                  <span className="amount">1,000</span>
                  <span className="period">/month</span>
                </div>
                <ul className="plan-features">
                  <li>Unlimited code scanning</li>
                  <li>Unlimited file analysis</li>
                  <li>All language support</li>
                  <li>Advanced vulnerability detection</li>
                  <li>Priority support</li>
                </ul>
                <div className="plan-footer">
                  <button
                    className="plan-subscribe-btn"
                    onClick={() => handleCheckout('enterprise-basic')}
                    disabled={checkoutLoading === 'enterprise-basic' || !!checkoutLoading}
                  >
                    {checkoutLoading === 'enterprise-basic' ? (
                      <>
                        <div className="spinner-small"></div>
                        <span>Processing...</span>
                      </>
                    ) : (
                      <>
                        <CreditCard size={18} />
                        <span>Subscribe Now</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
              <div className="pricing-plan-card popular">
                <div className="popular-badge">Most Popular</div>
                <h3>Professional Plan</h3>
                <div className="plan-price">
                  <span className="currency">$</span>
                  <span className="amount">1,500</span>
                  <span className="period">/month</span>
                </div>
                <ul className="plan-features">
                  <li>Unlimited code scanning</li>
                  <li>Unlimited file analysis</li>
                  <li>All language support</li>
                  <li>Advanced vulnerability detection</li>
                  <li>Vulnerability reports</li>
                  <li>Compliance reports</li>
                  <li>API access</li>
                  <li>Priority support</li>
                  <li>Custom integration support</li>
                </ul>
                <div className="plan-footer">
                  <button
                    className="plan-subscribe-btn plan-subscribe-btn-primary"
                    onClick={() => handleCheckout('enterprise-pro')}
                    disabled={checkoutLoading === 'enterprise-pro' || !!checkoutLoading}
                  >
                    {checkoutLoading === 'enterprise-pro' ? (
                      <>
                        <div className="spinner-small"></div>
                        <span>Processing...</span>
                      </>
                    ) : (
                      <>
                        <CreditCard size={18} />
                        <span>Subscribe Now</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
            {error && (
              <div className="error-message" style={{ marginTop: '16px' }}>
                {error}
              </div>
            )}
            {!isAuthenticated && (
              <button onClick={() => setShowPricing(false)} className="login-popup-back-btn">
                Back to Login
              </button>
            )}
          </div>
        ) : (
          <>
            <div className="login-popup-header">
              <h2>Scan Limit Reached</h2>
              <p className="login-popup-subtitle">
                You've used {scansUsed} of {scanLimit} free scans. Sign in to continue scanning or view our pricing plans.
              </p>
            </div>

            <div className="login-popup-tabs">
              <button
                className={`login-popup-tab ${!isRegister ? 'active' : ''}`}
                onClick={() => {
                  setIsRegister(false)
                  setError(null)
                }}
              >
                Login
              </button>
              <button
                className={`login-popup-tab ${isRegister ? 'active' : ''}`}
                onClick={() => {
                  setIsRegister(true)
                  setError(null)
                }}
              >
                Register
              </button>
            </div>

            <form onSubmit={handleEmailSubmit} className="login-popup-form">
              {isRegister && (
                <div className="form-group">
                  <label htmlFor="popup-name">Full Name</label>
                  <input
                    type="text"
                    id="popup-name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    required
                    disabled={loading}
                    placeholder="Enter your name"
                  />
                </div>
              )}
              <div className="form-group">
                <label htmlFor="popup-email">Email</label>
                <input
                  type="email"
                  id="popup-email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  disabled={loading}
                  placeholder="Enter your email"
                />
              </div>
              <div className="form-group">
                <label htmlFor="popup-password">Password</label>
                <input
                  type="password"
                  id="popup-password"
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
                className="login-popup-submit-btn"
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

            <div className="login-popup-divider">
              <span>OR</span>
            </div>

            <div className="login-popup-options">
              <button onClick={handleGitHubLogin} className="login-popup-btn github-btn">
                <Github size={18} />
                <span>Continue with GitHub</span>
              </button>
              <button onClick={handleGoogleLogin} className="login-popup-btn google-btn">
                <Mail size={18} />
                <span>Continue with Google</span>
              </button>
            </div>

            <div className="login-popup-pricing-section">
              <div className="login-popup-pricing-divider"></div>
              <button onClick={handleViewPricing} className="login-popup-pricing-btn">
                <CreditCard size={18} />
                <span>View Pricing Plans</span>
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

export default LoginPopup

