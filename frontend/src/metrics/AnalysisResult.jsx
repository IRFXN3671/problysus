import { motion } from 'framer-motion' // eslint-disable-line no-unused-vars

const AnalysisResult = ({ data }) => {
    const { riskScore, label, reasons, checks } = data

    const getScoreColorClass = (label) => {
        if (label === 'Safe') return 'safe'
        if (label === 'Suspicious') return 'suspicious'
        return 'fraudulent'
    }

    const scoreClass = getScoreColorClass(label)

    return (
        <div className="result-card glass-card">
            <div className={`score-circle ${scoreClass}`}>
                {riskScore}
            </div>

            <div className={`risk-label ${scoreClass}`}>
                {label}
            </div>

            <p style={{ textAlign: 'center', marginBottom: '2rem' }}>
                {data.recommendation}
            </p>

            {/* Progress Bar */}
            <div style={{ background: 'rgba(255,255,255,0.1)', borderRadius: '10px', height: '10px', overflow: 'hidden', marginBottom: '2rem' }}>
                <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${riskScore}%` }}
                    transition={{ duration: 1, ease: "easeOut" }}
                    style={{
                        height: '100%',
                        background: label === 'Safe' ? 'var(--success-color)' : label === 'Suspicious' ? 'var(--warning-color)' : 'var(--danger-color)'
                    }}
                />
            </div>

            <div className="details-grid">
                <div className="detail-item">
                    <span className="detail-icon">{checks.https ? '🔒' : '🔓'}</span>
                    <span>{checks.https ? 'Valid HTTPS' : 'No HTTPS'}</span>
                </div>
                <div className="detail-item">
                    <span className="detail-icon">📅</span>
                    <span>Domain Age: {checks.domainAgeDays >= 0 ? `${checks.domainAgeDays} days` : 'Unknown'}</span>
                </div>
                <div className="detail-item">
                    <span className="detail-icon">{!checks.blacklisted ? '✅' : '🚫'}</span>
                    <span>{checks.blacklisted ? 'On Blacklist' : 'Not Blacklisted'}</span>
                </div>
                <div className="detail-item">
                    <span className="detail-icon">{checks.suspiciousPatterns ? '⚠️' : '🛡️'}</span>
                    <span>{checks.suspiciousPatterns ? 'Suspicious Patterns' : 'Clean URL Patterns'}</span>
                </div>
                <div className="detail-item">
                    <span className="detail-icon">📄</span>
                    <span>Trust Pages: {checks.trustPagesFound.length > 0 ? checks.trustPagesFound.join(', ') : 'None'}</span>
                </div>
            </div>

            {reasons && reasons.length > 0 && (
                <div className={`reasons-list ${label === 'Safe' ? 'safe-reasons' : ''}`}>
                    <h3>Analysis Findings:</h3>
                    <ul>
                        {reasons.map((reason, index) => (
                            <li key={index}>{reason}</li>
                        ))}
                    </ul>
                </div>
            )}
        </div>
    )
}

export default AnalysisResult
