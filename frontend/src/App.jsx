import { useState } from 'react'
import axios from 'axios'
import UrlInput from './components/UrlInput'
import AnalysisResult from './metrics/AnalysisResult'
import './index.css'

function App() {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleAnalyze = async (url) => {
    setLoading(true)
    setError(null)
    setResult(null)
    
    try {
      // Assuming backend is running on port 5000
      const response = await axios.post('http://localhost:5000/analyze', { url })
      setResult(response.data)
    } catch (err) {
      setError(err.response?.data?.error || "Failed to analyze URL. Server might be down.")
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="container">
      <div className="glass-card fade-in" style={{ textAlign: 'center', marginBottom: '2rem' }}>
        <h1>Problysus</h1>
        <p>Universal Website Scam & Trust Detection</p>
      </div>

      <div className="glass-card fade-in" style={{ animationDelay: '0.1s' }}>
        <UrlInput onAnalyze={handleAnalyze} loading={loading} />
        
        {error && (
            <div style={{ color: 'var(--danger-color)', marginTop: '1rem', textAlign: 'center' }}>
                ⚠️ {error}
            </div>
        )}
      </div>

      {result && (
        <div className="fade-in" style={{ animationDelay: '0.2s' }}>
          <AnalysisResult data={result} />
        </div>
      )}
    </div>
  )
}

export default App
