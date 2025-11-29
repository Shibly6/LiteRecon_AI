import React, { useState, useEffect } from 'react';

const ToolSelector = ({ availableTools, selectedTools, onToolsChange }) => {
    const [selectAll, setSelectAll] = useState(false);

    // Group tools by category
    const groupedTools = {};
    Object.entries(availableTools || {}).forEach(([toolId, toolInfo]) => {
        const category = toolInfo.category || 'other';
        if (!groupedTools[category]) {
            groupedTools[category] = [];
        }
        groupedTools[category].push({ id: toolId, ...toolInfo });
    });

    const handleToggle = (toolId) => {
        if (selectedTools.includes(toolId)) {
            onToolsChange(selectedTools.filter(id => id !== toolId));
        } else {
            onToolsChange([...selectedTools, toolId]);
        }
    };

    const handleSelectAll = () => {
        if (selectAll) {
            onToolsChange([]);
        } else {
            const allAvailable = Object.entries(availableTools || {})
                .filter(([_, info]) => info.available)
                .map(([id, _]) => id);
            onToolsChange(allAvailable);
        }
        setSelectAll(!selectAll);
    };

    const categoryNames = {
        'port_scanner': 'Port Scanners',
        'web_scanner': 'Web Scanners',
        'smb_scanner': 'SMB/Network Scanners',
        'ssl_scanner': 'SSL/TLS Scanners',
        'other': 'Other Tools'
    };

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <label style={{ fontSize: '13px', color: 'var(--muted)', margin: 0 }}>
                    Scanning Tools
                </label>
                <button
                    type="button"
                    onClick={handleSelectAll}
                    className="btn-ghost"
                    style={{
                        padding: '4px 12px',
                        fontSize: '12px',
                        width: 'auto',
                        display: 'inline-block'
                    }}
                >
                    {selectAll ? 'Deselect All' : 'Select All Available'}
                </button>
            </div>

            <div style={{
                background: '#0f172a',
                border: '1px solid var(--border)',
                borderRadius: '10px',
                padding: '12px',
                maxHeight: '300px',
                overflowY: 'auto'
            }}>
                {Object.entries(groupedTools).map(([category, tools]) => (
                    <div key={category} style={{ marginBottom: '16px' }}>
                        <div style={{
                            fontSize: '11px',
                            color: 'var(--accent)',
                            fontWeight: '600',
                            marginBottom: '8px',
                            textTransform: 'uppercase',
                            letterSpacing: '0.5px'
                        }}>
                            {categoryNames[category] || category}
                        </div>

                        {tools.map(tool => (
                            <div
                                key={tool.id}
                                style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    padding: '8px',
                                    marginBottom: '4px',
                                    borderRadius: '6px',
                                    background: selectedTools.includes(tool.id) ? 'rgba(59, 130, 246, 0.1)' : 'transparent',
                                    cursor: tool.available ? 'pointer' : 'not-allowed',
                                    opacity: tool.available ? 1 : 0.5,
                                    transition: 'all 0.2s'
                                }}
                                onClick={() => tool.available && handleToggle(tool.id)}
                            >
                                <input
                                    type="checkbox"
                                    checked={selectedTools.includes(tool.id)}
                                    onChange={() => tool.available && handleToggle(tool.id)}
                                    disabled={!tool.available}
                                    style={{
                                        marginRight: '10px',
                                        cursor: tool.available ? 'pointer' : 'not-allowed',
                                        accentColor: 'var(--accent)'
                                    }}
                                />
                                <div style={{ flex: 1 }}>
                                    <div style={{
                                        fontSize: '13px',
                                        color: '#e2e8f0',
                                        fontWeight: '500',
                                        marginBottom: '2px'
                                    }}>
                                        {tool.name}
                                        {!tool.available && (
                                            <span style={{
                                                marginLeft: '8px',
                                                fontSize: '10px',
                                                padding: '2px 6px',
                                                background: '#dc2626',
                                                color: 'white',
                                                borderRadius: '4px',
                                                fontWeight: '600'
                                            }}>
                                                INSTALL REQUIRED
                                            </span>
                                        )}
                                    </div>
                                    <div style={{
                                        fontSize: '11px',
                                        color: 'var(--muted)'
                                    }}>
                                        {tool.description}
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                ))}
            </div>

            <div style={{
                marginTop: '8px',
                fontSize: '11px',
                color: 'var(--muted)',
                textAlign: 'center'
            }}>
                {selectedTools.length} tool{selectedTools.length !== 1 ? 's' : ''} selected
            </div>
        </div>
    );
};

export default ToolSelector;
