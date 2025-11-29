import React, { useState, useEffect } from 'react';
import ScanForm from './components/ScanForm';
import Results from './components/Results';
import SudoModal from './components/SudoModal';
import { startScan, getScanResult, getAvailableTools } from './api';

function App() {
  const [currentScanId, setCurrentScanId] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [availableTools, setAvailableTools] = useState({});
  const [showSudoModal, setShowSudoModal] = useState(false);
  const [pendingScan, setPendingScan] = useState(null);

  // Fetch available tools on mount
  useEffect(() => {
    const fetchTools = async () => {
      try {
        const data = await getAvailableTools();
        setAvailableTools(data.tools || {});
      } catch (error) {
        console.error("Failed to fetch tools", error);
      }
    };
    fetchTools();
  }, []);

  const handleScanStart = async (target, aiModel, selectedTools) => {
    // Check if any selected tool might need sudo
    const needsSudo = selectedTools.some(tool =>
      ['nmap', 'masscan', 'rustscan'].includes(tool)
    );

    if (needsSudo) {
      setPendingScan({ target, aiModel, selectedTools });
      setShowSudoModal(true);
    } else {
      executeScan(target, aiModel, selectedTools);
    }
  };

  const handleSudoSubmit = (password) => {
    setShowSudoModal(false);
    if (pendingScan) {
      // In a real implementation, you'd send the password to backend
      // For now, just proceed with the scan
      executeScan(pendingScan.target, pendingScan.aiModel, pendingScan.selectedTools, password);
      setPendingScan(null);
    }
  };

  const executeScan = async (target, aiModel, selectedTools, sudoPassword = null) => {
    setIsLoading(true);
    setScanResult(null);
    try {
      const { scan_id } = await startScan(target, aiModel, selectedTools, sudoPassword);
      setCurrentScanId(scan_id);
    } catch (error) {
      console.error("Failed to start scan", error);
      setIsLoading(false);
      alert("Failed to start scan. Check backend.");
    }
  };

  useEffect(() => {
    if (!currentScanId) return;

    const pollInterval = setInterval(async () => {
      try {
        const result = await getScanResult(currentScanId);
        setScanResult(result);
        if (result.status === 'completed' || result.status === 'failed') {
          setIsLoading(false);
          clearInterval(pollInterval);
        }
      } catch (error) {
        console.error("Failed to fetch scan result", error);
      }
    }, 2000);

    return () => clearInterval(pollInterval);
  }, [currentScanId]);

  return (
    <div className="container">
      <div className="panel">
        <h1>🛡️ LiteRecon_AI</h1>

        <ScanForm
          onScanStart={handleScanStart}
          isLoading={isLoading}
          availableTools={availableTools}
        />

        <Results result={scanResult} />

        <footer style={{ textAlign: 'center', fontSize: '11px', color: 'var(--muted)', marginTop: '32px', paddingTop: '20px', borderTop: '1px solid var(--border)' }}>
          &copy; {new Date().getFullYear()} Noor Elahi Ali Shibly. All rights reserved.
        </footer>
      </div>

      <SudoModal
        isOpen={showSudoModal}
        onClose={() => setShowSudoModal(false)}
        onSubmit={handleSudoSubmit}
      />
    </div>
  );
}

export default App;
