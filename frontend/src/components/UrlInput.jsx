import { useState } from 'react'

const UrlInput = ({ onAnalyze, loading }) => {
    const [url, setUrl] = useState('')

    const handleSubmit = (e) => {
        e.preventDefault()
        if (url.trim()) {
            onAnalyze(url)
        }
    }

    return (
        <form onSubmit={handleSubmit} className="input-section">
            <div className="input-wrapper">
                <input
                    type="text"
                    placeholder="Enter website URL (e.g. google.com)"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    disabled={loading}
                    autoFocus
                />
                <button type="submit" className="primary-btn" disabled={loading || !url.trim()}>
                    {loading ? (
                        <>
                            <span className="loader"></span> Analyzing...
                        </>
                    ) : (
                        'Analyze'
                    )}
                </button>
            </div>
        </form>
    )
}

export default UrlInput
