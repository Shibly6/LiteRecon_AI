"""
LLM Provider Module

This module supports multiple LLM providers for generating security scan summaries.
Currently active: Ollama (deepseek-r1:1.5b)
Commented out: OpenAI (ChatGPT), Google (Gemini), and additional local models

To enable a provider:
1. Uncomment the provider class
2. Set the API key in environment variables (for cloud providers)
3. Update the get_llm_provider() function to include the provider
"""

import requests
import json
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

# LLM Provider Configuration
LLM_CONFIG = {
    "ollama": {
        "url": "http://localhost:11434/api/generate",
        "active_models": ["deepseek-r1:1.5b"],  # Currently active
        "available_models": [
            "deepseek-r1:1.5b",
            "llama3.2",
            "llama3.2:1b",
            "llama3.2:3b", 
            "gpt-oss",
            "mistral",
            "mistral:7b",
            "codellama",
            "phi3",
            "qwen2.5"
        ]
    },
    # Uncomment to enable OpenAI (ChatGPT)
    # "openai": {
    #     "api_key": os.getenv("OPENAI_API_KEY", ""),
    #     "url": "https://api.openai.com/v1/chat/completions",
    #     "models": [
    #         "gpt-4",
    #         "gpt-4-turbo",
    #         "gpt-4o",
    #         "gpt-3.5-turbo"
    #     ]
    # },
    # Uncomment to enable Google Gemini
    # "gemini": {
    #     "api_key": os.getenv("GEMINI_API_KEY", ""),
    #     "url": "https://generativelanguage.googleapis.com/v1beta/models",
    #     "models": [
    #         "gemini-pro",
    #         "gemini-1.5-pro",
    #         "gemini-1.5-flash"
    #     ]
    # },
    # Uncomment to enable Anthropic Claude
    # "anthropic": {
    #     "api_key": os.getenv("ANTHROPIC_API_KEY", ""),
    #     "url": "https://api.anthropic.com/v1/messages",
    #     "models": [
    #         "claude-3-opus",
    #         "claude-3-sonnet",
    #         "claude-3-haiku"
    #     ]
    # }
}

# ============================================================================
# PROVIDER CLASSES
# ============================================================================

class LLMProvider:
    """Base class for all LLM providers"""
    
    def generate(self, prompt: str, model: str) -> str:
        """Generate response from LLM"""
        raise NotImplementedError("Subclasses must implement generate()")


class OllamaProvider(LLMProvider):
    """Ollama provider for local LLM models (ACTIVE)"""
    
    def __init__(self, url: str = "http://localhost:11434/api/generate"):
        self.url = url
    
    def generate(self, prompt: str, model: str) -> str:
        """Generate response using Ollama"""
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False
        }
        
        try:
            logger.info(f"Sending request to Ollama ({model})...")
            response = requests.post(self.url, json=payload, timeout=300)
            response.raise_for_status()
            result = response.json()
            return result.get("response", "No response content from LLM.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama request failed: {e}")
            return f"Error generating summary: {str(e)}. Ensure Ollama is running."


# ============================================================================
# COMMENTED OUT PROVIDERS (Uncomment to enable)
# ============================================================================

# class OpenAIProvider(LLMProvider):
#     """OpenAI (ChatGPT) provider for cloud-based LLM"""
#     
#     def __init__(self, api_key: str, url: str = "https://api.openai.com/v1/chat/completions"):
#         self.api_key = api_key
#         self.url = url
#     
#     def generate(self, prompt: str, model: str) -> str:
#         """Generate response using OpenAI API"""
#         headers = {
#             "Authorization": f"Bearer {self.api_key}",
#             "Content-Type": "application/json"
#         }
#         
#         payload = {
#             "model": model,
#             "messages": [
#                 {
#                     "role": "system",
#                     "content": "You are a cybersecurity analyst generating professional network security reports."
#                 },
#                 {
#                     "role": "user",
#                     "content": prompt
#                 }
#             ],
#             "temperature": 0.7,
#             "max_tokens": 2000
#         }
#         
#         try:
#             logger.info(f"Sending request to OpenAI ({model})...")
#             response = requests.post(self.url, headers=headers, json=payload, timeout=60)
#             response.raise_for_status()
#             result = response.json()
#             return result["choices"][0]["message"]["content"]
#         except requests.exceptions.RequestException as e:
#             logger.error(f"OpenAI request failed: {e}")
#             return f"Error generating summary with OpenAI: {str(e)}"


# class GeminiProvider(LLMProvider):
#     """Google Gemini provider for cloud-based LLM"""
#     
#     def __init__(self, api_key: str, url: str = "https://generativelanguage.googleapis.com/v1beta/models"):
#         self.api_key = api_key
#         self.base_url = url
#     
#     def generate(self, prompt: str, model: str) -> str:
#         """Generate response using Google Gemini API"""
#         url = f"{self.base_url}/{model}:generateContent?key={self.api_key}"
#         
#         payload = {
#             "contents": [
#                 {
#                     "parts": [
#                         {
#                             "text": prompt
#                         }
#                     ]
#                 }
#             ],
#             "generationConfig": {
#                 "temperature": 0.7,
#                 "maxOutputTokens": 2000
#             }
#         }
#         
#         try:
#             logger.info(f"Sending request to Google Gemini ({model})...")
#             response = requests.post(url, json=payload, timeout=60)
#             response.raise_for_status()
#             result = response.json()
#             return result["candidates"][0]["content"]["parts"][0]["text"]
#         except requests.exceptions.RequestException as e:
#             logger.error(f"Gemini request failed: {e}")
#             return f"Error generating summary with Gemini: {str(e)}"


# class AnthropicProvider(LLMProvider):
#     """Anthropic Claude provider for cloud-based LLM"""
#     
#     def __init__(self, api_key: str, url: str = "https://api.anthropic.com/v1/messages"):
#         self.api_key = api_key
#         self.url = url
#     
#     def generate(self, prompt: str, model: str) -> str:
#         """Generate response using Anthropic Claude API"""
#         headers = {
#             "x-api-key": self.api_key,
#             "anthropic-version": "2023-06-01",
#             "Content-Type": "application/json"
#         }
#         
#         payload = {
#             "model": model,
#             "messages": [
#                 {
#                     "role": "user",
#                     "content": prompt
#                 }
#             ],
#             "max_tokens": 2000,
#             "temperature": 0.7
#         }
#         
#         try:
#             logger.info(f"Sending request to Anthropic ({model})...")
#             response = requests.post(self.url, headers=headers, json=payload, timeout=60)
#             response.raise_for_status()
#             result = response.json()
#             return result["content"][0]["text"]
#         except requests.exceptions.RequestException as e:
#             logger.error(f"Anthropic request failed: {e}")
#             return f"Error generating summary with Claude: {str(e)}"


# ============================================================================
# PROVIDER FACTORY
# ============================================================================

def get_llm_provider(model: str) -> LLMProvider:
    """
    Get appropriate LLM provider based on model name.
    
    Currently only Ollama is active. To enable other providers:
    1. Uncomment the provider class above
    2. Set API key in environment variables
    3. Uncomment the corresponding section below
    """
    
    # Check if model is in Ollama models
    ollama_models = LLM_CONFIG["ollama"]["available_models"]
    if model in ollama_models:
        return OllamaProvider(LLM_CONFIG["ollama"]["url"])
    
    # Uncomment to enable OpenAI
    # openai_models = LLM_CONFIG.get("openai", {}).get("models", [])
    # if model in openai_models:
    #     api_key = LLM_CONFIG["openai"]["api_key"]
    #     if not api_key:
    #         raise ValueError("OPENAI_API_KEY environment variable not set")
    #     return OpenAIProvider(api_key, LLM_CONFIG["openai"]["url"])
    
    # Uncomment to enable Gemini
    # gemini_models = LLM_CONFIG.get("gemini", {}).get("models", [])
    # if model in gemini_models:
    #     api_key = LLM_CONFIG["gemini"]["api_key"]
    #     if not api_key:
    #         raise ValueError("GEMINI_API_KEY environment variable not set")
    #     return GeminiProvider(api_key, LLM_CONFIG["gemini"]["url"])
    
    # Uncomment to enable Anthropic
    # anthropic_models = LLM_CONFIG.get("anthropic", {}).get("models", [])
    # if model in anthropic_models:
    #     api_key = LLM_CONFIG["anthropic"]["api_key"]
    #     if not api_key:
    #         raise ValueError("ANTHROPIC_API_KEY environment variable not set")
    #     return AnthropicProvider(api_key, LLM_CONFIG["anthropic"]["url"])
    
    # Default to Ollama if model not recognized
    logger.warning(f"Model '{model}' not recognized, defaulting to Ollama")
    return OllamaProvider(LLM_CONFIG["ollama"]["url"])


# ============================================================================
# MAIN SUMMARIZATION FUNCTION
# ============================================================================

def summarize_scan(scan_data, ai_model="deepseek-r1:1.5b"):
    """
    Sends scan data to the configured LLM for comprehensive security report generation.
    
    Args:
        scan_data: Dictionary containing scan results from multiple tools
        ai_model: Model name (e.g., "deepseek-r1:1.5b", "gpt-4", "gemini-pro")
    
    Returns:
        str: Generated security report summary
    """
    logger.info(f"Generating scan summary using model: {ai_model}")
    
    # Extract data from multi-tool scan
    target = scan_data.get('target', 'Unknown')
    tools_used = scan_data.get('tools_used', [])
    vulnerabilities = scan_data.get('vulnerabilities', {})
    vuln_stats = scan_data.get('vulnerability_stats', {})
    recommendations = scan_data.get('recommendations', [])
    technologies = scan_data.get('technologies', [])
    
    # Extract ports and OS from tool results
    ports = []
    os_info = {}
    for result in scan_data.get('tool_results', []):
        if result.get('tool') in ['nmap_tcp', 'nmap'] and result.get('success'):
            ports = result.get('ports', [])
            os_info = result.get('os_detection', {})
            break
    
    # Build ports summary
    ports_text = "\n".join([
        f"Port {p['port']}/{p['protocol']}: {p['service']} {p.get('product', '')} {p.get('version', '')}"
        for p in ports[:20]  # Limit to first 20 ports
    ])
    
    # Determine ports status message
    if not ports and 'nmap_tcp' not in tools_used and 'nmap_udp' not in tools_used:
        ports_status = "Port scan not performed"
    elif not ports:
        ports_status = "No open ports detected"
    else:
        ports_status = ports_text

    # Build technologies summary
    tech_text = ", ".join(technologies) if technologies else "No web technologies detected"
    
    # Build vulnerability summary
    vuln_text = ""
    for severity in ['Critical', 'High', 'Medium', 'Low']:
        if severity in vulnerabilities:
            count = len(vulnerabilities[severity])
            vuln_text += f"\n{severity}: {count} findings"
            for vuln in vulnerabilities[severity][:3]:  # Show first 3 of each severity
                vuln_text += f"\n  - Port {vuln.get('port', 'N/A')}: {vuln.get('title', 'Unknown')}"
    
    # Construct comprehensive security report prompt
    prompt = f"""You are a cybersecurity analyst generating a professional network security report. Use the scan results provided to produce a structured report with the following sections:

**Target Information:**
- Target: {target}
- Tools Used: {', '.join(tools_used)}

**Open Ports:**
{ports_status}

**Web Technologies:**
{tech_text}

**Operating System:**
{os_info.get('name', 'Unknown')} (Accuracy: {os_info.get('accuracy', '0')}%)

**Vulnerability Findings:**
Total Vulnerabilities: {vuln_stats.get('total', 0)}
{vuln_text if vuln_text else "No vulnerabilities detected"}

**Recommendations:**
{chr(10).join(recommendations) if recommendations else "Continue regular security monitoring"}

Please provide a structured markdown report with:
1. **Executive Summary** (2-3 sentences highlighting overall security posture and key technologies found)
2. **Open Ports Table** (Port Number | Protocol | Service | Version) - State "Not Scanned" if applicable
3. **Web Technologies** (List identified technologies)
4. **Operating System Information**
5. **Vulnerability Analysis** (Summarize critical/high risks in simple, clear sentences)
6. **Security Recommendations** (Actionable steps to improve security)

Keep the language professional but concise. Highlight critical/high risks clearly."""
    
    # Get appropriate provider and generate summary
    try:
        provider = get_llm_provider(ai_model)
        summary = provider.generate(prompt, ai_model)
        return summary
    except Exception as e:
        logger.error(f"Failed to generate summary: {e}")
        return f"Error generating summary: {str(e)}"


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_available_models():
    """
    Get list of all available models across all providers.
    
    Returns:
        dict: Dictionary of provider names to their available models
    """
    available = {}
    
    # Ollama models (always available)
    available["ollama"] = LLM_CONFIG["ollama"]["available_models"]
    
    # Uncomment to include other providers
    # if "openai" in LLM_CONFIG and LLM_CONFIG["openai"]["api_key"]:
    #     available["openai"] = LLM_CONFIG["openai"]["models"]
    # 
    # if "gemini" in LLM_CONFIG and LLM_CONFIG["gemini"]["api_key"]:
    #     available["gemini"] = LLM_CONFIG["gemini"]["models"]
    # 
    # if "anthropic" in LLM_CONFIG and LLM_CONFIG["anthropic"]["api_key"]:
    #     available["anthropic"] = LLM_CONFIG["anthropic"]["models"]
    
    return available


def test_provider_connection(provider_name: str) -> bool:
    """
    Test if a provider is accessible and properly configured.
    
    Args:
        provider_name: Name of the provider (ollama, openai, gemini, anthropic)
    
    Returns:
        bool: True if provider is accessible, False otherwise
    """
    if provider_name == "ollama":
        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    # Uncomment to test other providers
    # elif provider_name == "openai":
    #     return bool(LLM_CONFIG.get("openai", {}).get("api_key"))
    # 
    # elif provider_name == "gemini":
    #     return bool(LLM_CONFIG.get("gemini", {}).get("api_key"))
    # 
    # elif provider_name == "anthropic":
    #     return bool(LLM_CONFIG.get("anthropic", {}).get("api_key"))
    
    return False
