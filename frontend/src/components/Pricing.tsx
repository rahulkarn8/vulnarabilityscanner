import { useState } from 'react'
import { Check, Zap, Building2, CreditCard, Lock, LogIn } from 'lucide-react'
import axios from 'axios'
import { useAuth } from '../contexts/AuthContext'
import { API_URL } from '../config'
import './Pricing.css'

interface PricingPlan {
  id: string
  name: string
  price: number
  features: string[]
  popular?: boolean
}

const plans: PricingPlan[] = [
  {
    id: 'enterprise-basic',
    name: 'Basic Plan',
    price: 1000,
    features: [
      'Unlimited code scanning',
      'Unlimited file analysis',
      'All language support',
      'Advanced vulnerability detection',
      'Priority support'
    ]
  },
  {
    id: 'enterprise-pro',
    name: 'Professional Plan',
    price: 1500,
    features: [
      'Unlimited code scanning',
      'Unlimited file analysis',
      'All language support',
      'Advanced vulnerability detection',
      'Vulnerability reports',
      'Compliance reports',
      'API access',
      'Priority support',
      'Custom integration support'
    ],
    popular: true
  }
]

function Pricing() {
  const { token, isAuthenticated } = useAuth()
  const [loading, setLoading] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showLoginPrompt, setShowLoginPrompt] = useState(false)

  const handleCheckout = async (planId: string) => {
    // Check if user is authenticated
    if (!isAuthenticated || !token) {
      setShowLoginPrompt(true)
      setError('Please log in to subscribe to a plan')
      return
    }

    setLoading(planId)
    setError(null)
    setShowLoginPrompt(false)

    try {
      // Create checkout session on backend
      const response = await axios.post(`${API_URL}/payment/create-checkout-session`, {
        plan_id: planId,
        success_url: `${window.location.origin}/pricing?success=true`,
        cancel_url: `${window.location.origin}/pricing?canceled=true`
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
      setLoading(null)
    }
  }

  const handleGitHubLogin = () => {
    window.location.href = `${API_URL}/auth/github/login`
  }

  const handleGoogleLogin = () => {
    window.location.href = `${API_URL}/auth/google/login`
  }

  // Check for success/cancel messages in URL
  const urlParams = new URLSearchParams(window.location.search)
  const success = urlParams.get('success')
  const canceled = urlParams.get('canceled')

  return (
    <div className="pricing-container">
      <div className="pricing-header">
        <div className="pricing-title">
          <Building2 size={32} />
          <h1>Enterprise Pricing</h1>
        </div>
        <p className="pricing-subtitle">
          Choose the plan that fits your organization's security scanning needs
        </p>
      </div>

      {success && (
        <div className="alert alert-success">
          <Check size={20} />
          <span>Payment successful! Your subscription is now active.</span>
        </div>
      )}

      {canceled && (
        <div className="alert alert-warning">
          <span>Payment was canceled. You can try again anytime.</span>
        </div>
      )}

      {error && (
        <div className="alert alert-error">
          <span>{error}</span>
        </div>
      )}

      {showLoginPrompt && !isAuthenticated && (
        <div className="alert alert-warning login-prompt">
          <LogIn size={20} />
          <div className="login-prompt-content">
            <p><strong>Login Required</strong></p>
            <p>Please log in to subscribe to a plan. Choose your preferred login method:</p>
            <div className="login-prompt-buttons">
              <button onClick={handleGitHubLogin} className="login-prompt-btn github-btn">
                <span>Continue with GitHub</span>
              </button>
              <button onClick={handleGoogleLogin} className="login-prompt-btn google-btn">
                <span>Continue with Google</span>
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="pricing-grid">
        {plans.map((plan) => (
          <div
            key={plan.id}
            className={`pricing-card ${plan.popular ? 'popular' : ''}`}
          >
            {plan.popular && (
              <div className="popular-badge">
                <Zap size={16} />
                <span>Most Popular</span>
              </div>
            )}

            <div className="plan-header">
              <h2>{plan.name}</h2>
              <div className="plan-price">
                <span className="currency">$</span>
                <span className="amount">{plan.price.toLocaleString()}</span>
                <span className="period">/month</span>
              </div>
            </div>

            <ul className="plan-features">
              {plan.features.map((feature, idx) => (
                <li key={idx}>
                  <Check size={18} />
                  <span>{feature}</span>
                </li>
              ))}
            </ul>

            <div className="plan-footer">
              <button
                className={`btn-checkout ${plan.popular ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => handleCheckout(plan.id)}
                disabled={loading === plan.id}
              >
                {loading === plan.id ? (
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
        ))}
      </div>

      <div className="pricing-footer">
        <div className="security-note">
          <Lock size={20} />
          <div>
            <h3>Secure Payment Processing</h3>
            <p>
              All payments are processed securely through Stripe. We never store your payment information.
              Your subscription can be canceled at any time.
            </p>
          </div>
        </div>

        <div className="pricing-faq">
          <h3>Frequently Asked Questions</h3>
          <div className="faq-grid">
            <div className="faq-item">
              <h4>What's included in the Basic Plan?</h4>
              <p>The Basic Plan includes unlimited code scanning and vulnerability detection, but does not include reports or API access.</p>
            </div>
            <div className="faq-item">
              <h4>Can I change plans later?</h4>
              <p>Yes, you can upgrade or downgrade your plan at any time. Changes take effect immediately.</p>
            </div>
            <div className="faq-item">
              <h4>Is there a free trial?</h4>
              <p>Contact our sales team for a custom trial period tailored to your needs.</p>
            </div>
            <div className="faq-item">
              <h4>What payment methods do you accept?</h4>
              <p>We accept all major credit cards, debit cards, and corporate payment methods through Stripe.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Pricing

