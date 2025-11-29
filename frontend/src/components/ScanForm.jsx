import React, { useState } from 'react';
import ToolSelector from './ToolSelector';

const ScanForm = ({ onScanStart, isLoading, availableTools }) => {
    const [target, setTarget] = useState('');
    const [aiModel, setAiModel] = useState('deepseek-r1:1.5b');
    const [selectedTools, setSelectedTools] = useState(['nmap_tcp']); // Default to nmap_tcp

    const handleSubmit = (e) => {
        e.preventDefault();
        if (target && selectedTools.length > 0) {
            onScanStart(target, aiModel, selectedTools);
        }
    };

    return (
        <>
            <div className="form-grid">
                <div>
                    <label htmlFor="target">Target</label>
                    <input
                        id="target"
                        className="input"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        placeholder="IP or domain (e.g., 192.168.1.10)"
                    />
                </div>

                <div>
                    <label htmlFor="aiModel">AI Model</label>
                    <select
                        id="aiModel"
                        className="select"
                        value={aiModel}
                        onChange={(e) => setAiModel(e.target.value)}
                    >
                        <option value="deepseek-r1:1.5b">DeepSeek R1 1.5B</option>
                        <option value="gemma3:1b">Gemma 3 1B</option>
                    </select>
                </div>
            </div>

            <div className="spacer"></div>

            <ToolSelector
                availableTools={availableTools}
                selectedTools={selectedTools}
                onToolsChange={setSelectedTools}
            />

            <div className="spacer"></div>

            <button
                id="startBtn"
                className="btn btn-primary"
                onClick={handleSubmit}
                disabled={isLoading || !target || selectedTools.length === 0}
            >
                {isLoading ? '⏳ Scanning...' : '🚀 Start Scan'}
            </button>
        </>
    );
};

export default ScanForm;
