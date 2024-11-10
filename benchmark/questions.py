# Dictionary to store questions by category
def q():
    return cybersecurity_questions

cybersecurity_questions = {
    "Fundamental Concepts": [
        "What is the CIA Triad in cybersecurity, and what does each component represent?",
        "Describe the difference between symmetric and asymmetric encryption.",
        "What is multi-factor authentication (MFA), and why is it important?",
        "Explain the concept of hashing and provide examples of hashing algorithms.",
        "What is the principle of 'least privilege,' and why is it essential for security?",
    ],
    "Network Security": [
        "How does a firewall work, and what types of firewalls are commonly used?",
        "Explain the concept of an Intrusion Detection System (IDS) vs. an Intrusion Prevention System (IPS).",
        "What are the common types of network attacks (e.g., DDoS, man-in-the-middle)?",
        "How does a VPN enhance network security, and what are some limitations?",
        "Describe the function of network segmentation and how it improves security.",
    ],
    "Web Security": [
        "What is Cross-Site Scripting (XSS), and how can it be prevented?",
        "Explain the difference between HTTP and HTTPS.",
        "How does Cross-Site Request Forgery (CSRF) work, and what defenses can be implemented?",
        "Describe SQL injection and list common ways to protect against it.",
        "What is Content Security Policy (CSP), and how does it help secure web applications?",
    ],
    "Application Security": [
        "What is secure coding, and why is it important?",
        "Explain the concept of input validation and its role in preventing attacks.",
        "How do secure software development practices (e.g., OWASP guidelines) protect applications?",
        "What is code injection, and what types of applications are vulnerable to it?",
        "Describe what buffer overflow vulnerabilities are and how they can be mitigated.",
    ],
    "Endpoint Security": [
        "What are the functions of antivirus software?",
        "How does endpoint detection and response (EDR) differ from traditional antivirus?",
        "Explain the concept of 'zero-day exploit' in the context of endpoint security.",
        "What are the best practices for securing mobile devices in an enterprise environment?",
        "Describe the process of hardening an operating system to improve security.",
    ],
    "Identity and Access Management (IAM)": [
        "What is the difference between authentication and authorization?",
        "Describe Single Sign-On (SSO) and its security advantages.",
        "Explain Role-Based Access Control (RBAC) vs. Attribute-Based Access Control (ABAC).",
        "What is identity federation, and how is it implemented in cloud services?",
        "Describe how session management is used to control user access in web applications.",
    ],
    "Cryptography": [
        "What is Public Key Infrastructure (PKI), and how does it work?",
        "Explain the difference between encryption and hashing.",
        "What is a digital signature, and how does it verify the authenticity of a message?",
        "Describe how Transport Layer Security (TLS) provides secure communication over networks.",
        "What are common cryptographic attacks (e.g., brute-force, birthday attack), and how can they be prevented?",
    ],
    "Threats and Vulnerabilities": [
        "What is the difference between a vulnerability, a threat, and a risk?",
        "Explain what phishing is and how to protect against it.",
        "What is social engineering, and what are common tactics attackers use?",
        "Describe what ransomware is and steps to defend against it.",
        "Explain the concept of Advanced Persistent Threats (APTs) and how they are detected.",
    ],
    "Incident Response and Management": [
        "What are the key steps in an incident response plan?",
        "How does digital forensics support incident response?",
        "Describe what a Security Operations Center (SOC) does.",
        "What is the role of SIEM (Security Information and Event Management) in detecting security incidents?",
        "Explain the importance of post-incident reviews and lessons learned.",
    ],
    "Compliance and Legal Aspects": [
        "What is GDPR, and how does it impact data protection practices?",
        "Describe the importance of compliance with standards like PCI-DSS.",
        "What is the difference between data privacy and data security?",
        "How does the CCPA affect companies operating in the United States?",
        "Explain the concept of data sovereignty and its implications for international data transfer.",
    ],
    "Cloud Security": [
        "What is shared responsibility in the context of cloud security?",
        "Explain the differences between IaaS, PaaS, and SaaS and their security implications.",
        "How does encryption work in a cloud environment?",
        "Describe what a Cloud Access Security Broker (CASB) is and its role.",
        "What are common cloud-specific security risks (e.g., misconfiguration, data loss)?",
    ],
    "Security Operations and Monitoring": [
        "What is log management, and why is it important in security monitoring?",
        "Explain the concept of threat intelligence and how it helps in defending against attacks.",
        "What are the benefits and limitations of using honeypots?",
        "Describe the MITRE ATT&CK framework and how it assists in threat detection.",
        "How does endpoint monitoring differ from network monitoring?",
    ],
    "Penetration Testing and Ethical Hacking": [
        "What is penetration testing, and what are its main phases?",
        "Describe what ethical hacking is and how it differs from malicious hacking.",
        "Explain the difference between black-box, white-box, and gray-box testing.",
        "What are the tools commonly used in penetration testing (e.g., Nmap, Metasploit)?",
        "How is vulnerability scanning different from penetration testing?",
    ],
    "Security in Emerging Technologies": [
        "How do blockchain and distributed ledger technologies impact cybersecurity?",
        "What are the security challenges related to IoT devices?",
        "Explain how machine learning can both improve and weaken cybersecurity.",
        "Describe the key security concerns for autonomous systems and robotics.",
        "What is quantum computing, and how might it impact current encryption standards?",
    ],
    "Security Policies and Governance": [
        "What is the purpose of a cybersecurity policy in an organization?",
        "Describe the concept of risk assessment and how it relates to cybersecurity planning.",
        "How do access control policies support organizational security?",
        "What is a Business Continuity Plan (BCP), and why is it essential?",
        "Explain the importance of employee training and awareness in cybersecurity.",
    ]
}

# Print all categories and their questions
for category, questions in cybersecurity_questions.items():
    print(f"\nCategory: {category}")
    for question in questions:
        print(f" - {question}")
        
   