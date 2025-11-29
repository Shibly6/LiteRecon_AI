# 🕵️‍♂️ LiteRecon_AI

**Advanced Network Reconnaissance & Vulnerability Analysis with AI-Powered Insights**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![React](https://img.shields.io/badge/react-19%2B-cyan)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20WSL-black)
![AI](https://img.shields.io/badge/AI-Local%20%7C%20Cloud-green)

LiteRecon_AI is a modern, full-stack cybersecurity reconnaissance platform that combines **11 industry-standard scanning tools** with **AI-powered analysis** to automate network security assessments. Generate comprehensive, professional PDF reports with actionable insights using local or cloud-based AI models.

> **⚠️ Legal Notice:** This tool is intended for **authorized security testing and educational purposes only**. Unauthorized scanning of networks you don't own or have permission to test is illegal.

---

## ✨ Key Features

### 🤖 **Multi-Provider AI Analysis**
- **Local AI**: DeepSeek-R1, Llama 3.2, Mistral, GPT-OSS (via Ollama) - **Privacy-first, no data leaves your machine**
- **Cloud AI** (Optional): OpenAI (GPT-4, GPT-3.5), Google Gemini, Anthropic Claude
- Intelligent vulnerability analysis, risk assessment, and remediation recommendations
- Natural language security reports for technical and non-technical audiences

### 🔍 **Comprehensive Scanning Arsenal**
| Tool | Purpose | Key Features |
|------|---------|--------------|
| **Nmap** | Port scanning & OS detection | TCP/UDP scans, service versioning, vulnerability scripts |
| **WhatWeb** | Web technology fingerprinting | CMS detection, server identification, framework analysis |
| **Feroxbuster** | Directory/file enumeration | Recursive brute-forcing, multi-threaded scanning |
| **Enum4Linux-ng** | SMB/NetBIOS enumeration | User/share enumeration, password policy extraction |
| **SSLyze** | SSL/TLS analysis | Cipher suite testing, certificate validation, vulnerability checks |
| **Nbtscan** | NetBIOS name scanning | Network host discovery, workgroup enumeration |
| **Onesixtyone** | SNMP community scanner | Community string brute-forcing |
| **Snmpwalk** | SNMP MIB walker | System information extraction via SNMP |
| **DNSRecon** | DNS enumeration | Zone transfers, reverse lookups, subdomain discovery |
| **AutoRecon** | Automated multi-tool enumeration | Comprehensive automated reconnaissance |

### 📊 **Professional Reporting**
- **Structured PDF Reports** with multiple tables per tool
- **Executive Summaries** for management
- **Technical Details** for security teams
- **AI-Generated Insights** at the end of each report
- **Customizable** report sections and styling

### 🎨 **Modern Web Interface**
- Responsive React-based dashboard
- Real-time scan progress tracking
- Multi-tool selection with visual feedback
- One-click PDF report downloads
- Scan history management

---

## 🛠️ Technology Stack

### Backend
- **Python 3.10+** - Core application logic
- **FastAPI** - High-performance async web framework
- **Uvicorn** - ASGI server
- **ReportLab** - Professional PDF generation
- **Requests** - HTTP client for AI APIs

### Frontend
- **React 19** - Modern UI library
- **Vite** - Lightning-fast build tool
- **Axios** - API communication
- **React Markdown** - Formatted AI response rendering

### AI/ML
- **Ollama** - Local LLM runtime (default)
- **OpenAI API** - ChatGPT integration (optional)
- **Google Gemini API** - Gemini integration (optional)
- **Anthropic API** - Claude integration (optional)

---

## 📋 Prerequisites

### Required Software

#### For Kali Linux (Native)
```bash
# System packages
sudo apt update && sudo apt upgrade -y

# Python and Node.js
sudo apt install python3 python3-pip python3-venv nodejs npm -y

# Scanning tools
sudo apt install nmap feroxbuster whatweb enum4linux-ng sslyze \
                 nbtscan onesixtyone snmp dnsrecon autorecon -y
```

#### For Windows (WSL 2)
1. **Install WSL 2** (PowerShell as Administrator):
   ```powershell
   wsl --install
   ```
   *Restart your computer after installation.*

2. **Install Kali Linux or Ubuntu** from Microsoft Store

3. **Inside WSL**, run the same commands as Kali Linux above

### AI Model Setup

#### Option 1: Local AI (Recommended - Privacy-First)
Install **Ollama** from [ollama.com](https://ollama.com/):

```bash
# Install Ollama (Linux/WSL)
curl -fsSL https://ollama.com/install.sh | sh

# Pull the default model
ollama pull deepseek-r1:1.5b

# Optional: Pull additional models
ollama pull llama3.2
ollama pull mistral
ollama pull gpt-oss
```

#### Option 2: Cloud AI (Optional)
For cloud-based AI, you'll need API keys:
- **OpenAI**: Get from [platform.openai.com](https://platform.openai.com/)
- **Google Gemini**: Get from [ai.google.dev](https://ai.google.dev/)
- **Anthropic**: Get from [console.anthropic.com](https://console.anthropic.com/)

---

## 🚀 Installation & Setup

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/Shibly6/LiteRecon_AI.git
cd LiteRecon_AI
```

### 2️⃣ Backend Setup
```bash
cd backend

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows WSL: source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 3️⃣ Frontend Setup
```bash
cd ../frontend

# Install Node.js dependencies
npm install
```

### 4️⃣ Configure AI Models (Optional)

#### For Local AI (Default - No Configuration Needed)
The application uses `deepseek-r1:1.5b` by default. No configuration required!

#### For Cloud AI (Optional)
To enable cloud AI providers, edit `backend/llm.py`:

1. **Set Environment Variables**:
   ```bash
   # Add to ~/.bashrc or ~/.zshrc
   export OPENAI_API_KEY="sk-your-openai-key-here"
   export GEMINI_API_KEY="your-gemini-key-here"
   export ANTHROPIC_API_KEY="sk-ant-your-anthropic-key-here"
   ```

2. **Uncomment Provider Code** in `backend/llm.py`:
   - Find the provider class (e.g., `OpenAIProvider`)
   - Uncomment the entire class
   - Uncomment the provider config in `LLM_CONFIG`
   - Uncomment the provider section in `get_llm_provider()`

3. **Restart Backend** to apply changes

---

## 🎯 Usage

### Starting the Application

#### Terminal 1: Start Backend
```bash
cd backend
source venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

#### Terminal 2: Start Frontend
```bash
cd frontend
npm run dev
```

#### Terminal 3: Start Ollama (if using local AI)
```bash
ollama serve
```

### Accessing the Application
Open your browser and navigate to:
👉 **http://localhost:5173**

### Running a Scan

1. **Enter Target**: IP address, domain, or subnet (e.g., `192.168.1.1`, `example.com`, `192.168.1.0/24`)

2. **Select AI Model**:
   - **Local**: `deepseek-r1:1.5b`, `llama3.2`, `mistral`, `gpt-oss`
   - **Cloud** (if configured): `gpt-4`, `gpt-3.5-turbo`, `gemini-pro`, `claude-3-sonnet`

3. **Choose Scanning Tools**: Select one or more tools based on your needs

4. **Enter Sudo Password**: Required for privileged scans (Nmap SYN scan, etc.)

5. **Start Scan**: Click "Start Scan" and wait for results

6. **Download Report**: Click "Download PDF Report" when scan completes

---

## 🤖 AI Model Configuration Guide

### Available AI Models

#### Local Models (via Ollama) - **Free & Private**

| Model | Size | Speed | Quality | Best For |
|-------|------|-------|---------|----------|
| `deepseek-r1:1.5b` | 1.5B | ⚡⚡⚡ | ⭐⭐⭐ | **Default** - Fast, efficient |
| `llama3.2` | 3B | ⚡⚡ | ⭐⭐⭐⭐ | Balanced performance |
| `llama3.2:1b` | 1B | ⚡⚡⚡ | ⭐⭐ | Ultra-fast, lightweight |
| `mistral` | 7B | ⚡ | ⭐⭐⭐⭐⭐ | High quality analysis |
| `gpt-oss` | Various | ⚡⚡ | ⭐⭐⭐ | Open source GPT alternative |
| `codellama` | 7B+ | ⚡ | ⭐⭐⭐⭐ | Code-focused analysis |
| `phi3` | 3.8B | ⚡⚡ | ⭐⭐⭐⭐ | Microsoft's efficient model |
| `qwen2.5` | Various | ⚡⚡ | ⭐⭐⭐⭐ | Alibaba's latest model |

#### Cloud Models - **Paid & High Quality**

| Provider | Model | Speed | Quality | Cost |
|----------|-------|-------|---------|------|
| **OpenAI** | `gpt-4` | ⚡ | ⭐⭐⭐⭐⭐ | $$$ |
| **OpenAI** | `gpt-4-turbo` | ⚡⚡ | ⭐⭐⭐⭐⭐ | $$ |
| **OpenAI** | `gpt-3.5-turbo` | ⚡⚡⚡ | ⭐⭐⭐⭐ | $ |
| **Google** | `gemini-pro` | ⚡⚡ | ⭐⭐⭐⭐ | $$ |
| **Google** | `gemini-1.5-pro` | ⚡⚡ | ⭐⭐⭐⭐⭐ | $$ |
| **Anthropic** | `claude-3-opus` | ⚡ | ⭐⭐⭐⭐⭐ | $$$ |
| **Anthropic** | `claude-3-sonnet` | ⚡⚡ | ⭐⭐⭐⭐ | $$ |

### How to Add/Enable AI Models

#### Adding Local Models (Ollama)

1. **Pull the model**:
   ```bash
   ollama pull llama3.2
   ```

2. **Verify installation**:
   ```bash
   ollama list
   ```

3. **Use in LiteRecon_AI**: The model will automatically appear in the dropdown (if added to `LLM_CONFIG`)

4. **Add to configuration** (if not listed):
   Edit `backend/llm.py`:
   ```python
   LLM_CONFIG = {
       "ollama": {
           "available_models": [
               "deepseek-r1:1.5b",
               "your-new-model-name",  # Add here
               # ... other models
           ]
       }
   }
   ```

#### Enabling Cloud AI Providers

##### Example: Enabling OpenAI (ChatGPT)

1. **Get API Key** from [platform.openai.com/api-keys](https://platform.openai.com/api-keys)

2. **Set Environment Variable**:
   ```bash
   # Add to ~/.bashrc or ~/.zshrc
   export OPENAI_API_KEY="sk-your-actual-api-key-here"
   
   # Reload shell configuration
   source ~/.bashrc
   ```

3. **Edit `backend/llm.py`**:

   **Step 3a**: Uncomment the OpenAI configuration (around line 40):
   ```python
   # BEFORE (commented):
   # "openai": {
   #     "api_key": os.getenv("OPENAI_API_KEY", ""),
   #     ...
   # },
   
   # AFTER (uncommented):
   "openai": {
       "api_key": os.getenv("OPENAI_API_KEY", ""),
       "url": "https://api.openai.com/v1/chat/completions",
       "models": ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"]
   },
   ```

   **Step 3b**: Uncomment the `OpenAIProvider` class (around line 100):
   ```python
   # Remove the comment markers (#) from the entire class
   class OpenAIProvider(LLMProvider):
       """OpenAI (ChatGPT) provider for cloud-based LLM"""
       # ... rest of the class
   ```

   **Step 3c**: Uncomment OpenAI in `get_llm_provider()` (around line 280):
   ```python
   # BEFORE:
   # openai_models = LLM_CONFIG.get("openai", {}).get("models", [])
   # if model in openai_models:
   #     ...
   
   # AFTER:
   openai_models = LLM_CONFIG.get("openai", {}).get("models", [])
   if model in openai_models:
       api_key = LLM_CONFIG["openai"]["api_key"]
       if not api_key:
           raise ValueError("OPENAI_API_KEY environment variable not set")
       return OpenAIProvider(api_key, LLM_CONFIG["openai"]["url"])
   ```

4. **Restart Backend**:
   ```bash
   # Stop the backend (Ctrl+C)
   # Restart it
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

5. **Use in Application**: Select `gpt-4` or `gpt-3.5-turbo` from the AI model dropdown

##### Enabling Google Gemini

Follow the same steps as OpenAI, but:
- Get API key from [ai.google.dev](https://ai.google.dev/)
- Set `GEMINI_API_KEY` environment variable
- Uncomment `GeminiProvider` class and configuration
- Use models: `gemini-pro`, `gemini-1.5-pro`

##### Enabling Anthropic Claude

Follow the same steps as OpenAI, but:
- Get API key from [console.anthropic.com](https://console.anthropic.com/)
- Set `ANTHROPIC_API_KEY` environment variable
- Uncomment `AnthropicProvider` class and configuration
- Use models: `claude-3-opus`, `claude-3-sonnet`, `claude-3-haiku`

### Testing AI Provider Connection

```bash
cd backend
source venv/bin/activate
python -c "from llm import test_provider_connection; print('Ollama:', test_provider_connection('ollama'))"
```

---

## 📊 Report Features

### Generated Report Sections

Each PDF report includes:

1. **Title & Target Information**
2. **Tool-Specific Sections** (for each selected tool):
   - **Nmap TCP**: Open Ports, OS Detection, Vulnerabilities/Scripts
   - **Nmap UDP**: UDP Ports, UDP Script Results
   - **WhatWeb**: Web Technologies
   - **Feroxbuster**: Discovered Resources
   - **Enum4Linux**: SMB Users, Shares, Password Policy
   - **SSLyze**: Supported Ciphers, Certificate Details, Vulnerability Scan
   - **Nbtscan**: NetBIOS Hosts
   - **Onesixtyone**: SNMP Communities
   - **Snmpwalk**: SNMP MIB Data
   - **DNSRecon**: DNS Records
   - **AutoRecon**: Service Summary, Overall Vulnerabilities
3. **AI Analysis Summary** (at the end):
   - Executive Summary
   - Vulnerability Analysis
   - Security Recommendations
   - Risk Assessment

---

## 🔧 Troubleshooting

### Common Issues

#### "Ollama connection failed"
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If not running, start it
ollama serve
```

#### "Tool not found" errors
```bash
# Install missing tools
sudo apt install <tool-name>

# Verify installation
which nmap
which feroxbuster
```

#### "Permission denied" for scans
- Make sure you entered the sudo password in the UI
- Verify your user has sudo privileges: `sudo -v`

#### Frontend not connecting to backend
- Check backend is running on port 8000: `curl http://localhost:8000/api/tools`
- Verify CORS settings in `backend/main.py`

#### Cloud AI not working
- Verify API key is set: `echo $OPENAI_API_KEY`
- Check you uncommented all required sections in `llm.py`
- Restart backend after making changes

---

## 📁 Project Structure

```
LiteRecon_AI/
├── backend/
│   ├── main.py                 # FastAPI application
│   ├── llm.py                  # Multi-provider AI integration
│   ├── tool_scanners.py        # Scanning tool implementations
│   ├── report_parsers.py       # Report table generators
│   ├── pdf_generator.py        # PDF report generation
│   ├── vulnerability_parser.py # Vulnerability aggregation
│   ├── tool_detector.py        # Tool availability detection
│   ├── scanner.py              # Legacy Nmap scanner
│   └── requirements.txt        # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── App.jsx            # Main React component
│   │   ├── components/        # React components
│   │   ├── api.js             # API client
│   │   └── index.css          # Styles
│   ├── package.json           # Node.js dependencies
│   └── vite.config.js         # Vite configuration
└── README.md                  # This file
```

---

## 🎓 Use Cases

- **Penetration Testing**: Automated reconnaissance phase
- **Security Audits**: Comprehensive network assessment
- **Bug Bounty**: Initial target enumeration
- **Education**: Learn network security concepts
- **Red Team Exercises**: Automated information gathering
- **Compliance**: Regular security posture checks

---

## 🔐 Security Considerations

- **Always obtain written permission** before scanning any network
- **Use responsibly** - aggressive scans can impact network performance
- **Protect API keys** - never commit them to version control
- **Review reports** before sharing - they may contain sensitive information
- **Local AI is recommended** for sensitive environments (no data leaves your machine)

---

## 🗺️ Roadmap

- [ ] Web-based scan scheduling
- [ ] Multi-target scanning
- [ ] Custom scan profiles
- [ ] Integration with vulnerability databases (CVE, NVD)
- [ ] Export to JSON/CSV formats
- [ ] Dark mode UI
- [ ] Scan comparison feature
- [ ] API authentication

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/AmazingFeature`
3. Commit your changes: `git commit -m 'Add AmazingFeature'`
4. Push to the branch: `git push origin feature/AmazingFeature`
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 for Python code
- Use ESLint for JavaScript/React code
- Add comments for complex logic
- Update documentation for new features

---

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.

---

## 👨‍💻 Author

**Shibly**
- GitHub: [@Shibly6](https://github.com/Shibly6)
- Repository: [LiteRecon_AI](https://github.com/Shibly6/LiteRecon_AI)

---

## 🙏 Acknowledgments

- **Ollama** - Local LLM runtime
- **DeepSeek** - Efficient AI model
- **Nmap** - Network scanning
- **FastAPI** - Modern Python web framework
- **React** - UI library
- All open-source tool developers

---

## 📞 Support

If you encounter issues or have questions:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Search existing [GitHub Issues](https://github.com/Shibly6/LiteRecon_AI/issues)
3. Create a new issue with:
   - Detailed description
   - Steps to reproduce
   - System information (OS, Python version, etc.)
   - Error messages/logs

---

## ⚖️ Disclaimer

This tool is provided for educational and authorized testing purposes only. The authors and contributors are not responsible for any misuse or damage caused by this tool. Always ensure you have explicit permission before scanning any network or system you do not own.

**Use at your own risk. Happy (ethical) hacking! 🎯**
