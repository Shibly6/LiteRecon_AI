import React, { useState, useEffect } from 'react';
import { verifySudoPassword } from '../api';

const SudoModal = ({ isOpen, onClose, onSubmit }) => {
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [attempts, setAttempts] = useState(0);
    const [isVerifying, setIsVerifying] = useState(false);
    const [isLocked, setIsLocked] = useState(false);

    // Reset state when modal opens
    useEffect(() => {
        if (isOpen) {
            setPassword('');
            setError('');
            setAttempts(0);
            setIsVerifying(false);
            setIsLocked(false);
        }
    }, [isOpen]);

    if (!isOpen) return null;

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (isLocked) return;

        setIsVerifying(true);
        setError('');

        try {
            const result = await verifySudoPassword(password);

            if (result.success) {
                onSubmit(password);
                setPassword('');
            } else {
                const newAttempts = attempts + 1;
                setAttempts(newAttempts);
                setPassword(''); // Clear password on error

                if (newAttempts >= 3) {
                    setError('sudo: 3 incorrect password attempts');
                    setIsLocked(true);
                    // Close modal after a delay or let user close
                    setTimeout(() => {
                        onClose();
                    }, 2000);
                } else {
                    setError('Sorry, try again.');
                }
            }
        } catch (err) {
            setError('Verification failed. Please try again.');
        } finally {
            setIsVerifying(false);
        }
    };

    return (
        <div className="modal-overlay" onClick={isLocked ? undefined : onClose}>
            <div className="modal" onClick={(e) => e.stopPropagation()}>
                <h2>🔒 Sudo Password Required</h2>
                <p>Some scanning tools require elevated privileges. Please enter your sudo password to continue.</p>

                <form onSubmit={handleSubmit}>
                    <label htmlFor="sudo-password">Password</label>
                    <input
                        id="sudo-password"
                        type="password"
                        className={`input ${error ? 'input-error' : ''}`}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Enter sudo password"
                        autoFocus
                        disabled={isVerifying || isLocked}
                    />

                    {error && (
                        <div className="error-message" style={{ color: 'var(--error)', marginTop: '8px', fontSize: '0.9rem' }}>
                            {error}
                        </div>
                    )}

                    <div className="modal-buttons">
                        <button
                            type="button"
                            className="btn btn-ghost"
                            onClick={onClose}
                            disabled={isVerifying}
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            className="btn btn-primary"
                            disabled={!password || isVerifying || isLocked}
                        >
                            {isVerifying ? 'Verifying...' : 'Continue'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default SudoModal;
