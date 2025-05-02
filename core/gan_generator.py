import os
import random
import re
import datetime
import hashlib
from config import USE_GPT4ALL, GPT4ALL_MODEL_PATH, USE_OPENAI, OPENAI_API_KEY, PRE_GENERATED_DIR
from utils.helpers import generate_random_filename, green, yellow
from utils.file_utils import generate_fake_content

# GPT4All
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

# OpenAI
if USE_OPENAI:
    try:
        import openai
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
    except Exception as e:
        print(f"Error setting up OpenAI: {e}")
        USE_OPENAI = False

def safe_filename(name, max_len=100):
    name = re.sub(r'[<>:"/\\|?*\n\r\t]', '_', name)
    name = re.sub(r'_+', '_', name).strip("_ ")
    return name[:max_len]

def generate_with_openai(context):
    try:
        # Enhanced, more detailed prompt to get better decoy filenames
        prompt = f"""You're a cybersecurity deception specialist creating honeypot files. Based on the attacker behavior in the logs below, create 3 highly enticing, realistic decoy filenames that would be irresistible targets.

The filenames should:
1. Appear to contain high-value data (credentials, configurations, or sensitive documents)
2. Match enterprise naming conventions (snake_case, kebab-case, CamelCase)
3. Include realistic dates, versions, or environment indicators where appropriate
4. Have appropriate file extensions (.json, .xml, .conf, .yaml, .txt, .pdf, .docx, etc.)
5. Specifically match the attack patterns seen in these logs:

Logs:
{context}

Return exactly 3 filenames only, one per line. Make them realistic enough to deceive sophisticated attackers.
"""
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You create realistic honeypot decoy filenames that would attract the interest of attackers based on their observed behavior."},
                {"role": "user", "content": prompt}
            ]
        )
        results = response.choices[0].message.content.splitlines()
        return [line for line in results if line.strip()][:3]  # Filter empty lines and limit to 3 results
    except Exception as e:
        print(f"Error with OpenAI API: {e}")
        return [generate_improved_random_filename() for _ in range(3)]

def generate_with_gpt4all(context):
    try:
        # Enhanced prompt with more specificity and examples
        prompt = f"""
You are a cybersecurity deception expert specializing in honeypots and threat intelligence.
Your job is to create realistic, high-value decoy file names that attackers would likely target, based on the observed behavior in the following logs.

Guidelines:
- Use common attacker-targeted keywords (e.g., password, secret, config, backup, ssh, financial).
- Match names to one of these categories: documents, credentials, configs.
- Use naming conventions seen in enterprise environments (e.g., snake_case, kebab-case, or CamelCase).
- The names should appear plausible and enticing to attackers but contain no real sensitive data.
- Each name should reflect or be inspired by the attacker's tactics, targets, or patterns seen in the logs.
- Include extensions like .txt, .conf, .json, .docx, .log, .yaml, .xml, .properties, or .env
- Include company-like identifiers, project names, or environment indicators (dev, staging, prod)

Examples of good decoy names:
- aws_prod_credentials_backup.json
- database_connection_strings.conf
- employee_salary_data_2025Q1.xlsx
- firewall_rules_external_access.yaml
- vpn_admin_certificates.pem

Logs:
{context}

Return only 3 decoy filenames, one per line. Make them extremely convincing.
"""
        results = gpt_model.generate(prompt, max_tokens=100).splitlines()
        return [line for line in results if line.strip()][:3]  # Filter empty lines and limit to 3 results
    except Exception as e:
        print(f"Error with GPT4All: {e}")
        return [generate_improved_random_filename() for _ in range(3)]

def extract_keywords_from_logs(log_text):
    """Extract potential keywords from logs for better filename generation"""
    # Common keywords attackers look for
    interesting_patterns = [
        r'(?:\/[a-zA-Z0-9_\-\.]+)+',  # Paths
        r'(?:auth|admin|root|config|backup|password|secret|key|token|ssh|ftp|db|database)',  # Security keywords
        r'\b(?:get|post|put|delete)\b',  # HTTP methods
        r'\b(?:sql|script|cmd|exec)\b',  # Attack types
        r'\b(?:[a-zA-Z0-9_-]+\.(?:php|aspx|jsp|cgi))\b'  # Common web files
    ]
    
    results = []
    for pattern in interesting_patterns:
        matches = re.findall(pattern, log_text, re.IGNORECASE)
        results.extend(matches)
    
    # Extract words that might be useful
    words = re.findall(r'\b[a-zA-Z]{4,}\b', log_text)
    results.extend([w for w in words if w.lower() not in ('error', 'warning', 'info', 'debug')])
    
    return list(set([r.lower() for r in results if r]))[:5]  # Limit to 5 unique keywords

def generate_improved_random_filename():
    """Generate more realistic random filenames based on common patterns"""
    today = datetime.datetime.now()
    date_formats = [
        f"{today.year}-{today.month:02d}",
        f"{today.year}_{today.month:02d}_{today.day:02d}",
        f"{today.strftime('%b').lower()}_{today.year}",
        f"Q{(today.month-1)//3+1}_{today.year}"
    ]
    
    company_prefixes = ["acme", "globex", "initech", "skynet", "umbrella", "stark", "wayne", "oscorp"]
    environments = ["dev", "test", "staging", "prod", "production", "internal", "external"]
    
    document_patterns = [
        f"{random.choice(company_prefixes)}_financial_report_{random.choice(date_formats)}.xlsx",
        f"project_{random.randint(1000, 9999)}_proposal.docx",
        f"meeting_notes_{random.choice(date_formats)}.pdf",
        f"{random.choice(company_prefixes)}_business_plan.pptx",
        f"employee_data_export_{random.choice(date_formats)}.csv"
    ]
    
    credential_patterns = [
        f"aws_{random.choice(environments)}_credentials.json",
        f"api_keys_{random.choice(date_formats)}.txt",
        f"database_connection_strings_{random.choice(environments)}.conf",
        f"ssh_private_keys_{random.choice(environments)}.tar.gz",
        f"{random.choice(company_prefixes)}_admin_passwords.kdbx"
    ]
    
    config_patterns = [
        f"server_config_{random.choice(environments)}.yaml",
        f"firewall_rules_{random.choice(environments)}.conf",
        f"network_settings_{random.choice(date_formats)}.xml",
        f"vpn_configuration_{random.choice(environments)}.ovpn",
        f"docker_compose_v{random.randint(1, 3)}.{random.randint(0, 9)}.yml"
    ]
    
    # Select a category and a pattern
    categories = [document_patterns, credential_patterns, config_patterns]
    selected_category = random.choice(categories)
    return random.choice(selected_category)

def analyze_context_for_target(log_summary):
    """Analyze logs to determine what kind of attack is happening"""
    patterns = {
        'web': ['http', 'https', 'www', 'html', 'php', 'aspx', 'apache', 'nginx'],
        'database': ['sql', 'mongodb', 'postgres', 'mysql', 'oracle', 'db', 'query'],
        'auth': ['login', 'password', 'auth', 'ssh', 'ftp', 'telnet', 'rdp'],
        'admin': ['admin', 'root', 'sudo', 'su', 'administrator'],
        'config': ['config', 'settings', 'env', 'properties', 'yml', 'yaml', 'json'],
        'code': ['git', 'source', 'src', 'code', 'repo', 'script']
    }
    
    attack_types = {}
    log_summary_lower = log_summary.lower()
    
    for attack_type, keywords in patterns.items():
        for keyword in keywords:
            if keyword in log_summary_lower:
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
    
    # Default to 'auth' if nothing detected
    if not attack_types:
        return 'auth'
    
    # Return the most likely attack type
    return max(attack_types, key=attack_types.get)

def generate_targeted_decoy(attack_type, keywords=None):
    """Generate a decoy specifically targeting the detected attack type"""
    if keywords is None:
        keywords = []
    
    today = datetime.datetime.now()
    date_str = f"{today.year}-{today.month:02d}-{today.day:02d}"
    environments = ["dev", "test", "staging", "production", "prod"]
    
    # Pick an environment with bias toward production
    env_weights = [0.1, 0.1, 0.2, 0.3, 0.3]  # Production is more tempting
    env = random.choices(environments, weights=env_weights)[0]
    
    company_names = ["acme", "globex", "initech", "cyberdyne", "umbrella"]
    company = random.choice(company_names)
    
    # Use a keyword if available
    keyword = ""
    if keywords:
        keyword = random.choice(keywords)
        # Clean up the keyword
        keyword = re.sub(r'[^a-zA-Z0-9_-]', '', keyword)
        if keyword:
            keyword = f"_{keyword}"
    
    if attack_type == 'web':
        web_files = [
            f"website_{env}_credentials.json",
            f"{company}_admin_portal{keyword}_config.yaml",
            f"web_server_access_logs_{date_str}.log"
        ]
        return random.choice(web_files)
    
    elif attack_type == 'database':
        db_files = [
            f"database{keyword}_connection_strings.conf",
            f"{company}_db_credentials_{env}.json",
            f"sql_queries_backup_{date_str}.sql"
        ]
        return random.choice(db_files)
        
    elif attack_type == 'auth':
        auth_files = [
            f"user_passwords{keyword}_hashed.txt",
            f"ssh_keys_{env}_{date_str}.tar.gz",
            f"{company}_ldap_credentials.properties"
        ]
        return random.choice(auth_files)
    
    elif attack_type == 'admin':
        admin_files = [
            f"admin{keyword}_accounts.json",
            f"root_access_config_{env}.yaml",
            f"{company}_privileged_users.csv"
        ]
        return random.choice(admin_files)
    
    elif attack_type == 'config':
        config_files = [
            f"system{keyword}_configuration_{env}.json",
            f"network_settings_{company}_{date_str}.xml",
            f"app_secrets_{env}.properties"
        ]
        return random.choice(config_files)
    
    elif attack_type == 'code':
        code_files = [
            f"source_code{keyword}_backup.zip",
            f"git_credentials_{company}.txt",
            f"deployment_script_{env}.sh"
        ]
        return random.choice(code_files)
    
    else:
        # Fallback to general high-value files
        general_files = [
            f"important{keyword}_credentials.json",
            f"{company}_confidential_data_{date_str}.xlsx",
            f"backup_configuration_{env}.yaml"
        ]
        return random.choice(general_files)

def generate_decoys_from_logs(log_summary, output_count=3):
    print(green("[+] Generating decoys based on log analysis..."))

    categories = ["documents", "credentials", "configs"]
    for category in categories:
        category_dir = os.path.join(PRE_GENERATED_DIR, category)
        os.makedirs(category_dir, exist_ok=True)

    # First try to use AI-based generation
    try:
        if USE_GPT4ALL and "gpt_model" in globals():
            suggestions = generate_with_gpt4all(log_summary)
        elif USE_OPENAI and "client" in globals():
            suggestions = generate_with_openai(log_summary)
        else:
            print(yellow("[!] No AI backend available, using enhanced file generator"))
            suggestions = []
    except Exception as e:
        print(f"Error generating suggestions: {e}")
        suggestions = []

    # If AI generation failed or returned insufficient results, supplement with smarter random generation
    if len(suggestions) < output_count:
        # Extract useful information from logs
        keywords = extract_keywords_from_logs(log_summary)
        attack_type = analyze_context_for_target(log_summary)
        
        # Generate targeted decoys based on the detected attack type
        while len(suggestions) < output_count:
            if random.random() < 0.7:  # 70% chance of targeted generation
                filename = generate_targeted_decoy(attack_type, keywords)
            else:  # 30% chance of improved random generation
                filename = generate_improved_random_filename()
            suggestions.append(filename)

    # Clean up filenames
    valid_suggestions = []
    for name in suggestions:
        if isinstance(name, str) and name.strip():
            cleaned_name = safe_filename(name.strip())
            # Only add .txt extension if no extension present
            if not re.search(r'\.\w{1,5}$', cleaned_name):
                cleaned_name += ".txt"
            valid_suggestions.append(cleaned_name)

    # Ensure we have enough valid suggestions
    while len(valid_suggestions) < output_count:
        valid_suggestions.append(generate_random_filename())

    # Create the actual files
    for name in valid_suggestions[:output_count]:
        category = random.choice(categories)
        path = os.path.join(PRE_GENERATED_DIR, category, name)
        with open(path, "w") as f:
            f.write(generate_fake_content())
        print(f"    [+] Generated: {path} in category {category}")