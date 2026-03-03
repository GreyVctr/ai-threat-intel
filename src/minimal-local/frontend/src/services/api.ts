import axios, { AxiosError } from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      // Clear token and redirect to login
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// Auth API
export const authApi = {
  login: async (username: string, password: string) => {
    const response = await api.post('/api/v1/auth/login', { username, password })
    return response.data
  },
  logout: async () => {
    const response = await api.post('/api/v1/auth/logout')
    return response.data
  },
  me: async () => {
    const response = await api.get('/api/v1/auth/me')
    return response.data
  },
}

// Threats API
export const threatsApi = {
  list: async (params?: {
    page?: number
    per_page?: number
    threat_type?: string
    severity_min?: number
    severity_max?: number
    source?: string
  }) => {
    const response = await api.get('/api/v1/threats', { params })
    return response.data
  },
  get: async (id: string, include_enrichment = true) => {
    const response = await api.get(`/api/v1/threats/${id}`, {
      params: { include_enrichment },
    })
    return response.data
  },
  create: async (data: any) => {
    const response = await api.post('/api/v1/threats', data)
    return response.data
  },
  update: async (id: string, data: any) => {
    const response = await api.put(`/api/v1/threats/${id}`, data)
    return response.data
  },
  delete: async (id: string) => {
    await api.delete(`/api/v1/threats/${id}`)
  },
}

// Search API
export const searchApi = {
  search: async (params: {
    q?: string
    threat_type?: string
    testability?: string
    severity_min?: number
    severity_max?: number
    date_from?: string
    date_to?: string
    page?: number
    per_page?: number
  }) => {
    const response = await api.get('/api/v1/search', { params })
    return response.data
  },
  statistics: async () => {
    const response = await api.get('/api/v1/search/statistics')
    return response.data
  },
  threatTypes: async () => {
    const response = await api.get('/api/v1/search/threat-types')
    return response.data
  },
  recent: async (limit = 10) => {
    const response = await api.get('/api/v1/threats/recent', { params: { limit } })
    return response.data
  },
  highSeverity: async (severity_threshold = 7, limit = 10) => {
    const response = await api.get('/api/v1/threats/high-severity', {
      params: { severity_threshold, limit },
    })
    return response.data
  },
}

// Sources API
export const sourcesApi = {
  list: async () => {
    const response = await api.get('/api/v1/sources')
    return response.data
  },
  create: async (data: any) => {
    const response = await api.post('/api/v1/sources', data)
    return response.data
  },
  update: async (id: string, data: any) => {
    const response = await api.put(`/api/v1/sources/${id}`, data)
    return response.data
  },
  delete: async (id: string) => {
    await api.delete(`/api/v1/sources/${id}`)
  },
}

// Health API
export const healthApi = {
  check: async () => {
    const response = await api.get('/api/v1/health')
    return response.data
  },
}

// System Status API
export const systemApi = {
  status: async () => {
    const response = await api.get('/api/v1/system/status')
    return response.data
  },
  llmAnalysisStats: async () => {
    const response = await api.get('/api/v1/system/llm-analysis-stats')
    return response.data
  },
  retryFailedLLM: async (limit = 100) => {
    const response = await api.post(`/api/v1/system/retry-failed-llm?limit=${limit}`)
    return response.data
  },
  ollamaConfig: async () => {
    const response = await api.get('/api/v1/system/ollama-config')
    return response.data
  },
  threatTypeInfo: async () => {
    const response = await api.get('/api/v1/system/threat-type-info')
    return response.data
  },
  collectNow: async () => {
    const response = await api.post('/api/v1/system/collect-now')
    return response.data
  },
}

export default api
