import axios from 'axios';

const API_URL = 'http://localhost:8000/api';

export const getAvailableTools = async () => {
    const response = await axios.get(`${API_URL}/tools`);
    return response.data;
};

export const verifySudoPassword = async (password) => {
    try {
        const response = await axios.post(`${API_URL}/verify-sudo`, { password });
        return response.data;
    } catch (error) {
        return { success: false, error: error.message };
    }
};

export const startScan = async (target, aiModel, selectedTools, sudoPassword = null) => {
    const response = await axios.post(`${API_URL}/scan`, {
        target,
        ai_model: aiModel,
        selected_tools: selectedTools,
        sudo_password: sudoPassword
    });
    return response.data;
};

export const getScanResult = async (scanId) => {
    const response = await axios.get(`${API_URL}/scan/${scanId}`);
    return response.data;
};

export const downloadPDF = (scanId) => {
    window.open(`${API_URL}/scan/${scanId}/download-pdf`, '_blank');
};
