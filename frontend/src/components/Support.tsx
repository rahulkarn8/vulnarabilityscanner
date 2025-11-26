import { useState } from 'react'
import axios from 'axios'
import { API_URL } from '../config'
import './Support.css'

function Support() {
  const [email, setEmail] = useState('')
  const [issue, setIssue] = useState('')
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!email.trim() || !issue.trim()) {
      setMessage({ type: 'error', text: 'Please fill in all fields' })
      return
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email)) {
      setMessage({ type: 'error', text: 'Please enter a valid email address' })
      return
    }

    setLoading(true)
    setMessage(null)

    try {
      const response = await axios.post(`${API_URL}/support/send-email`, {
        email: email.trim(),
        issue: issue.trim()
      })

      if (response.data.success) {
        setMessage({ type: 'success', text: 'Your message has been sent successfully! We will get back to you soon.' })
        setEmail('')
        setIssue('')
      } else {
        setMessage({ type: 'error', text: response.data.message || 'Failed to send message. Please try again.' })
      }
    } catch (error: any) {
      console.error('Error sending support email:', error)
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.detail || error.message || 'Failed to send message. Please try again later.' 
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="support-container">
      <div className="support-content">
        <h1 className="support-title">Contact Support</h1>
        <p className="support-subtitle">
          Have a question or need help? Send us a message and we'll get back to you as soon as possible.
        </p>

        <form className="support-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="email">Your Email Address</label>
            <input
              type="email"
              id="email"
              name="email"
              placeholder="your.email@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="issue">Issue or Question</label>
            <textarea
              id="issue"
              name="issue"
              placeholder="Please describe your issue or question in detail..."
              value={issue}
              onChange={(e) => setIssue(e.target.value)}
              required
              disabled={loading}
              rows={8}
            />
          </div>

          {message && (
            <div className={`support-message ${message.type}`}>
              {message.text}
            </div>
          )}

          <button 
            type="submit" 
            className="support-submit-btn"
            disabled={loading}
          >
            {loading ? 'Sending...' : 'Send Message'}
          </button>
        </form>

        <div className="support-info">
          <p>
            <strong>Response Time:</strong> We typically respond within 24-48 hours during business days.
          </p>
          <p>
            <strong>Email:</strong> support@daifend.com
          </p>
        </div>
      </div>
    </div>
  )
}

export default Support

