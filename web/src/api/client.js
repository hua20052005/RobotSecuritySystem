import axios from 'axios'

const baseURL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8010'

const api = axios.create({
  baseURL,
  timeout: 180000,
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('rss_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

export default api
