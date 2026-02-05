import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from './stores/authStore'
import { ThemeProvider } from './contexts/ThemeContext'
import Layout from './components/Layout'
import Dashboard from './components/Dashboard'
import ThreatList from './components/ThreatList'
import ThreatDetail from './components/ThreatDetail'
import SearchPage from './components/SearchPage'
import SourcesManager from './components/SourcesManager'
import Settings from './components/Settings'
import Login from './components/Login'

function App() {
  const { isAuthenticated } = useAuthStore()

  return (
    <ThemeProvider>
      <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            isAuthenticated ? (
              <Layout>
                <Dashboard />
              </Layout>
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />
        <Route
          path="/threats"
          element={
            isAuthenticated ? (
              <Layout>
                <ThreatList />
              </Layout>
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />
        <Route
          path="/threats/:id"
          element={
            isAuthenticated ? (
              <Layout>
                <ThreatDetail />
              </Layout>
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />
        <Route
          path="/search"
          element={
            isAuthenticated ? (
              <Layout>
                <SearchPage />
              </Layout>
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />
        <Route
          path="/sources"
          element={
            isAuthenticated ? (
              <Layout>
                <SourcesManager />
              </Layout>
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />
        <Route
          path="/settings"
          element={
            isAuthenticated ? (
              <Layout>
                <Settings />
              </Layout>
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />
      </Routes>
    </Router>
    </ThemeProvider>
  )
}

export default App
