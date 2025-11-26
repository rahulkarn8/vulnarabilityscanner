import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react'
import axios from 'axios'
import { API_URL } from '../config'

interface User {
  id: number
  email: string
  name: string
  provider: string
  avatar_url?: string
}

interface AuthContextType {
  user: User | null
  token: string | null
  login: (token: string) => void
  logout: () => void
  isAuthenticated: boolean
  loading: boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

interface AuthProviderProps {
  children: ReactNode
}

export const AuthProvider = ({ children }: AuthProviderProps) => {
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchUser = useCallback(async (authToken: string) => {
    try {
      console.log('Fetching user with token:', authToken.substring(0, 20) + '...')
      console.log('API_URL:', API_URL)
      const response = await axios.get(`${API_URL}/auth/me`, {
        headers: {
          Authorization: `Bearer ${authToken}`
        }
      })
      console.log('User fetched successfully:', response.data)
      setUser(response.data)
      setLoading(false)
    } catch (error: any) {
      console.error('Error fetching user:', error)
      console.error('Error details:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status,
        statusText: error.response?.statusText
      })
      // If token is invalid, clear it
      setUser(null)
      setToken(null)
      localStorage.removeItem('auth_token')
      setLoading(false)
    }
  }, [API_URL])

  const login = useCallback((authToken: string) => {
    console.log('Login function called with token:', authToken.substring(0, 20) + '...')
    setToken(authToken)
    localStorage.setItem('auth_token', authToken)
    // Fetch user after setting token
    fetchUser(authToken).catch((error) => {
      console.error('Error in fetchUser during login:', error)
    })
  }, [fetchUser])

  // Load token and user from localStorage on mount
  useEffect(() => {
    const savedToken = localStorage.getItem('auth_token')
    if (savedToken) {
      setToken(savedToken)
      fetchUser(savedToken)
    } else {
      setLoading(false)
    }
  }, [fetchUser])

  // Handle OAuth callback
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const tokenParam = urlParams.get('token')
    const userIdParam = urlParams.get('user_id')
    const errorParam = urlParams.get('error')

    console.log('OAuth callback check:', {
      hasToken: !!tokenParam,
      hasUserId: !!userIdParam,
      hasError: !!errorParam,
      fullUrl: window.location.href,
      search: window.location.search
    })

    // Check for OAuth errors first
    if (errorParam) {
      const errorDescription = urlParams.get('error_description') || errorParam
      console.error('OAuth error:', errorParam, errorDescription)
      alert(`Login failed: ${errorDescription}`)
      // Clean up URL
      window.history.replaceState({}, document.title, window.location.pathname)
      setLoading(false)
      return
    }

    // Handle OAuth callback - check for token in query params (from backend redirect)
    if (tokenParam) {
      console.log('OAuth callback received, token found:', tokenParam.substring(0, 20) + '...')
      console.log('User ID:', userIdParam)
      // Save token and fetch user
      const savedToken = localStorage.getItem('auth_token')
      if (!savedToken || savedToken !== tokenParam) {
        console.log('Logging in with new token')
        login(tokenParam)
      } else {
        console.log('Token already saved, but fetching user again to ensure state is updated')
        // Even if token is the same, fetch user to ensure state is updated
        fetchUser(tokenParam)
      }
      // Clean up URL - remove query params
      const newUrl = window.location.pathname
      window.history.replaceState({}, document.title, newUrl)
    } else {
      // No token in URL, check if we have a saved token
      const savedToken = localStorage.getItem('auth_token')
      if (savedToken && !user) {
        console.log('No token in URL but found saved token, fetching user')
        setToken(savedToken)
        fetchUser(savedToken)
      } else if (!savedToken) {
        console.log('No token found in URL or localStorage')
        setLoading(false)
      }
    }
  }, [login, fetchUser, user])

  const logout = () => {
    setUser(null)
    setToken(null)
    localStorage.removeItem('auth_token')
    // Optionally call logout endpoint
    axios.post(`${API_URL}/auth/logout`).catch(() => {
      // Ignore errors on logout
    })
  }

  const isAuthenticated = !!user && !!token

  // Debug logging
  useEffect(() => {
    console.log('Auth state changed:', {
      hasUser: !!user,
      hasToken: !!token,
      isAuthenticated,
      loading,
      userEmail: user?.email,
      userName: user?.name
    })
  }, [user, token, isAuthenticated, loading])

  return (
    <AuthContext.Provider value={{ user, token, login, logout, isAuthenticated, loading }}>
      {children}
    </AuthContext.Provider>
  )
}

