import React from 'react';
import ReactMarkdown from 'react-markdown';
import { downloadPDF } from '../api';

const Results = ({ result }) => {
    const [isRawVisible, setIsRawVisible] = React.useState(false);

    if (!result) return null;

    const { status, summary, raw_data, error, id } = result;

    if (status === 'running') {
        return (
            <section className="results" aria-live="polite">
                <div className="muted" style={{ marginBottom: '8px' }}>Results</div>
                <div className="summary">Scan in progress... This may take a few minutes.</div>
            </section>
        );
    }

    if (status === 'failed') {
        return (
            <section className="results" aria-live="polite">
                <div className="muted" style={{ marginBottom: '8px' }}>Results</div>
                <div className="summary" style={{ color: 'red' }}>Scan Failed: {error}</div>
            </section>
        );
    }

    return (
        <section className="results" aria-live="polite">
            <div className="muted" style={{ marginBottom: '8px' }}>Results</div>

            <div className="summary" id="summary">
                <ReactMarkdown>{summary}</ReactMarkdown>
            </div>

            <div
                className={`raw-toggle ${!isRawVisible ? 'raw-collapsed' : ''}`}
                id="rawToggle"
                role="button"
                tabIndex="0"
                aria-expanded={isRawVisible}
                aria-controls="rawOutput"
                onClick={() => setIsRawVisible(!isRawVisible)}
            >
                <div className="raw-label"><span className="chev">▾</span> Raw Output</div>
                <div className="muted" id="rawSize">
                    {isRawVisible ? `${JSON.stringify(raw_data, null, 2).length} chars` : 'hidden'}
                </div>
            </div>

            <pre
                className={`raw-output ${isRawVisible ? 'open' : ''}`}
                id="rawOutput"
                aria-hidden={!isRawVisible}
            >
                {JSON.stringify(raw_data, null, 2)}
            </pre>

            <div className="spacer"></div>

            <div style={{ display: 'flex', gap: '10px', flexDirection: 'column' }}>
                <button
                    className="btn btn-primary"
                    onClick={() => downloadPDF(id)}
                >
                    Download PDF Report
                </button>

                <button
                    className="btn btn-ghost"
                    onClick={() => {
                        const element = document.createElement("a");
                        const reportContent = `Scan Report\n\nSummary:\n${summary}\n\nRaw Data:\n${JSON.stringify(raw_data, null, 2)}`;
                        const file = new Blob([reportContent], { type: 'text/plain' });
                        element.href = URL.createObjectURL(file);
                        element.download = "scan_report.txt";
                        document.body.appendChild(element);
                        element.click();
                    }}
                >
                    Download Text Report
                </button>
            </div>
        </section>
    );
};

export default Results;
