import os
import json
import re
import datetime
from config import USE_OPENAI, OPENAI_API_KEY, USE_GPT4ALL, GPT4ALL_MODEL_PATH, LOG_FILE
from utils.helpers import yellow, green, red, generate_random_filename

# GPT4All setup
if USE_GPT4ALL:
    try:
        from gpt4all import GPT4All
        gpt_model = GPT4All(
            model_name=os.path.basename(GPT4ALL_MODEL_PATH),
            model_path=os.path.dirname(GPT4ALL_MODEL_PATH),
            allow_download=False
        )
    except Exception as e:
        print(f"Error loading GPT4All model: {e}")
        USE_GPT4ALL = False

# OpenAI setup
if USE_OPENAI:
    try:
        import openai
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
    except Exception as e:
        print(f"Error setting up OpenAI: {e}")
        USE_OPENAI = False

def load_logs():
    if not os.path.exists(LOG_FILE):
        return "No logs available."
    try:
        with open(LOG_FILE, "r") as f:
            log_content = f.read()
            # Limit log content to prevent context window issues
            # Take last 1000 characters if log is too long
            if len(log_content) > 1000:
                return "..." + log_content[-1000:]
            return log_content
    except Exception as e:
        return f"Error reading logs: {e}"

def extract_iocs_from_logs(log_data):
    """Extract potential Indicators of Compromise from log data"""
    results = {
        'ips': set(),
        'paths': set(),
        'commands': set(),
        'usernames': set()
    }
    
    # Extract IP addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    results['ips'].update(re.findall(ip_pattern, log_data))
    
    # Extract file paths
    path_pattern = r'(?:/[a-zA-Z0-9_\-\.]+)+'
    results['paths'].update(re.findall(path_pattern, log_data))
    
    # Extract potential commands
    cmd_pattern = r'\b(?:wget|curl|bash|sh|python|perl|nc|nmap|apt|ssh|sudo)\b'
    results['commands'].update(re.findall(cmd_pattern, log_data))
    
    # Extract potential usernames
    user_pattern = r'\b(?:admin|root|user\d+|www-data|apache|nginx|postgres|oracle|ubuntu|ec2-user)\b'
    results['usernames'].update(re.findall(user_pattern, log_data))
    
    return results

def perform_basic_analysis(logs):
    """Perform basic analysis when AI is not available"""
    iocs = extract_iocs_from_logs(logs)
    
    threat_level = "Low"
    if len(iocs['ips']) > 3:
        threat_level = "Medium"
    if any(cmd in logs.lower() for cmd in ['wget', 'curl', 'bash', 'python']):
        threat_level = "High"
    
    analysis = []
    analysis.append(f"Threat Level: {threat_level}")
    
    if iocs['ips']:
        analysis.append(f"Suspicious IPs: {', '.join(list(iocs['ips'])[:5])}")
    
    if iocs['commands']:
        analysis.append(f"Suspicious Commands: {', '.join(list(iocs['commands'])[:5])}")
    
    if iocs['paths']:
        analysis.append(f"Targeted Paths: {', '.join(list(iocs['paths'])[:3])}")
    
    if "password" in logs.lower() or "login" in logs.lower() or "auth" in logs.lower():
        analysis.append("Behavior: Credential brute forcing attempt detected")
    elif "admin" in logs.lower() or "config" in logs.lower():
        analysis.append("Behavior: Admin interface probing detected")
    elif "wp-" in logs.lower() or "php" in logs.lower():
        analysis.append("Behavior: Web application scanning detected")
    else:
        analysis.append("Behavior: General reconnaissance activity")
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    analysis.append(f"Analysis Time: {timestamp}")
    
    return "\n".join(analysis)

def analyze_logs_with_openai(log_data):
    try:
        # Enhanced OpenAI prompt with structured output request
        system_prompt = """You are an expert cybersecurity analyst specializing in honeypot analysis. 
When examining honeypot logs, provide detailed insights organized into these sections:

1. THREAT ASSESSMENT - Overall threat level (Low/Medium/High/Critical) with brief justification
2. ATTACK VECTORS - Primary techniques and attack patterns observed
3. IOCs - Key Indicators of Compromise (IPs, commands, payloads, file paths)
4. ACTOR PROFILE - Likely motivation and sophistication level
5. RECOMMENDATIONS - Specific defensive actions based on this activity

Structure your analysis clearly with these section headers and provide specific, actionable insights."""

        user_prompt = f"""Analyze these honeypot logs and provide your expert assessment:

```
{log_data}
```

Focus on identifying attack patterns, malicious indicators, and providing actionable defensive recommendations."""

        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.7
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"Error with OpenAI API: {e}")
        return perform_basic_analysis(log_data)

def analyze_logs_with_gpt4all(log_data):
    # Enhanced prompt with more structure and focus
    prompt = f"""You are a cybersecurity analyst examining honeypot logs. Provide a concise but thorough analysis.

LOGS:
{log_data}

Your analysis should include:
1. THREAT LEVEL: Rate the severity (Low/Medium/High/Critical) and explain why
2. ATTACK VECTORS: What techniques or patterns are visible?
3. KEY IOCs: List important IPs, commands, or payloads observed
4. ACTOR PROFILE: What kind of attacker is this (script kiddie, organized, APT)?
5. RECOMMENDATIONS: What specific defensive actions should be taken?

Provide a brief but comprehensive analysis focusing on these elements.
"""
    try:
        output = gpt_model.generate(prompt, max_tokens=300)
        return output.strip()
    except Exception as e:
        print(f"Error with GPT4All: {e}")
        return perform_basic_analysis(log_data)

def save_analysis_results(analysis_text, filename="analysis_history.json"):
    """Save analysis results to a JSON history file"""
    try:
        history_file = os.path.join(os.path.dirname(LOG_FILE), filename)
        timestamp = datetime.datetime.now().isoformat()
        
        # Create a structured record
        analysis_record = {
            "timestamp": timestamp,
            "analysis": analysis_text,
        }
        
        # Extract threat level if present
        threat_match = re.search(r"Threat\s+(?:Level|Assessment):\s*(Low|Medium|High|Critical)", 
                                analysis_text, re.IGNORECASE)
        if threat_match:
            analysis_record["threat_level"] = threat_match.group(1)
        
        # Extract IPs if present
        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', analysis_text)
        if ip_matches:
            analysis_record["suspicious_ips"] = list(set(ip_matches))
        
        # Load existing history or create new
        if os.path.exists(history_file):
            try:
                with open(history_file, 'r') as f:
                    history = json.load(f)
            except json.JSONDecodeError:
                history = {"analyses": []}
        else:
            history = {"analyses": []}
        
        # Add new analysis and keep only the last 50
        history["analyses"].append(analysis_record)
        history["analyses"] = history["analyses"][-50:]
        
        # Save updated history
        with open(history_file, 'w') as f:
            json.dump(history, f, indent=2)
            
        return True
    except Exception as e:
        print(f"Error saving analysis results: {e}")
        return False

def generate_threat_intelligence_summary(analysis_text):
    """Generate a more concise threat intelligence summary from the analysis"""
    summary_lines = []
    
    # Extract threat level
    threat_match = re.search(r"Threat\s+(?:Level|Assessment):\s*(Low|Medium|High|Critical)", 
                            analysis_text, re.IGNORECASE)
    if threat_match:
        threat_level = threat_match.group(1)
        if threat_level.lower() == "high" or threat_level.lower() == "critical":
            summary_lines.append(f"{red('[!]')} THREAT LEVEL: {threat_level}")
        elif threat_level.lower() == "medium":
            summary_lines.append(f"{yellow('[!]')} THREAT LEVEL: {threat_level}")
        else:
            summary_lines.append(f"{green('[+]')} THREAT LEVEL: {threat_level}")
    
    # Extract attack vectors
    vector_section = re.search(r"ATTACK VECTORS:\s*(.*?)(?:\n\n|\n[A-Z0-9 ]+:)", 
                              analysis_text, re.DOTALL | re.IGNORECASE)
    if vector_section:
        vector_text = vector_section.group(1).strip()
        summary_lines.append(f"Attack Vectors: {vector_text[:100]}{'...' if len(vector_text) > 100 else ''}")
    
    # Extract IOCs (IPs)
    iocs = extract_iocs_from_logs(analysis_text)
    if iocs['ips']:
        summary_lines.append(f"Suspicious IPs: {', '.join(list(iocs['ips'])[:5])}")
    
    # Extract recommendations
    rec_section = re.search(r"RECOMMENDATIONS:\s*(.*?)(?:\n\n|\Z)", 
                           analysis_text, re.DOTALL | re.IGNORECASE)
    if rec_section:
        rec_text = rec_section.group(1).strip()
        summary_lines.append(f"Key Recommendation: {rec_text.split('.')[0]}")
    
    return "\n".join(summary_lines)

def run_log_analysis():
    print(yellow("[+] Running AI log analysis..."))
    logs = load_logs()

    if logs.strip() == "No logs available." or not logs.strip():
        fallback_result = "No logs found for analysis. System appears to be in initial setup phase."
        print(yellow("[!] " + fallback_result))
        return fallback_result

    try:
        if USE_GPT4ALL and 'gpt_model' in globals():
            print("[GPT4All] Processing logs...")
            result = analyze_logs_with_gpt4all(logs)
            print(green("[+] GPT4All analysis complete"))
        elif USE_OPENAI and 'client' in globals():
            print("[OpenAI] Processing logs...")
            result = analyze_logs_with_openai(logs)
            print(green("[+] OpenAI analysis complete"))
        else:
            print(yellow("[!] No AI backend configured. Using basic analysis engine"))
            result = perform_basic_analysis(logs)
    except Exception as e:
        print(red(f"[!] Analysis error: {e}"))
        result = perform_basic_analysis(logs)
    
    # Save analysis results for historical tracking
    save_analysis_results(result)
    
    # Generate and print a concise summary
    summary = generate_threat_intelligence_summary(result)
    if summary:
        print("\n--- THREAT INTELLIGENCE SUMMARY ---")
        print(summary)
        print("--- FULL ANALYSIS AVAILABLE IN LOGS ---\n")
    else:
        print(result)
    
    return result