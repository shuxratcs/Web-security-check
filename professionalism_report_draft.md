# Companion Report: Professionalism Aspects of the SentinelAI Web Security Scanner

**Word Count: ~2100 words**

---

## 1. Introduction

SentinelAI is an AI-powered web vulnerability scanner designed to identify security weaknesses in web applications. The tool performs active testing across ten security categories, including SQL Injection, Cross-Site Scripting (XSS), security header analysis, SSL/TLS certificate verification, sensitive file discovery, cookie security auditing, information disclosure detection, CORS misconfiguration, clickjacking protection, and Content Security Policy analysis. As a security testing tool, SentinelAI operates in a domain where social responsibility, ethical practice, legal compliance, and security considerations are not merely theoretical concerns but are fundamental to the artefact's design and implementation. This report examines these professionalism aspects in detail, demonstrating how each has been addressed throughout the project's development.

---

## 2. Social Impact

### 2.1 Introduction

Web security tools occupy a unique position in the technology landscape as dual-use technologies — instruments that can serve both constructive and destructive purposes. The social impact of SentinelAI must therefore be examined from both perspectives.

### 2.2 Beneficial Impact

The primary social benefit of SentinelAI lies in the **democratisation of cybersecurity**. Commercial vulnerability scanners such as Burp Suite Professional (PortSwigger, 2024) and Acunetix (Invicti, 2024) carry annual licence costs ranging from $449 to over $4,500, placing them beyond the reach of small businesses, independent developers, and educational institutions. According to the IBM Cost of a Data Breach Report (IBM Security, 2024), the average cost of a data breach reached $4.88 million in 2024, with small organisations disproportionately affected. SentinelAI addresses this disparity by providing a free, open-source alternative that runs entirely on localhost without requiring cloud subscriptions or external dependencies.

Furthermore, the tool has significant **educational value**. By presenting scan results through an intuitive visual interface with categorised findings and remediation guidance, SentinelAI functions as a learning platform for students and junior developers. The OWASP Foundation (2021) emphasises that awareness and education are critical first steps in addressing web application security, and SentinelAI aligns with this objective by making vulnerability detection accessible and understandable.

The National Cyber Security Centre's Cyber Security Breaches Survey (NCSC, 2024) reports that 50% of businesses experienced a cyber-attack in the preceding 12 months. Tools like SentinelAI contribute to reducing this figure by enabling proactive vulnerability identification before exploitation occurs.

### 2.3 Detrimental Impact

Conversely, the dual-use nature of SentinelAI presents risks. The tool sends active payloads — including SQL injection strings and XSS vectors — to target servers. In the hands of a malicious actor, this capability could be employed to identify vulnerabilities for exploitation rather than remediation. Schneier (2015) discusses this inherent tension in security tools, noting that "the same tools used to defend are used to attack."

Additionally, there is a risk of **false assurance**: a "Secure" result from SentinelAI does not guarantee the absence of all vulnerabilities. The tool tests a finite set of vectors and cannot replicate the depth of a comprehensive manual penetration test. Users must understand these limitations to avoid a dangerous overreliance on automated results.

### 2.4 Mitigations Implemented

To address these concerns, several safeguards were integrated into SentinelAI. A mandatory consent checkbox requires users to confirm authorisation before scanning. A legal disclaimer on the interface explicitly references the Computer Misuse Act 1990, warning against unauthorised use. Furthermore, the results interface clearly displays confidence percentages alongside each finding, discouraging absolute reliance on any single result.

---

## 3. Ethical Issues

### 3.1 Introduction

The ethical dimensions of a security scanning tool are substantial, as the tool inherently involves probing systems for weaknesses — an activity that sits at the boundary between defensive security research and potential intrusion.

### 3.2 Dual-Use Dilemma

SentinelAI exemplifies what the Menlo Report (Dittrich and Kenneally, 2012) describes as a technology requiring careful ethical governance. Unlike passive analysis tools, SentinelAI performs **active testing**: it sends crafted payloads to target servers and analyses responses for indicators of vulnerability. This active approach, while necessary for effective detection, raises ethical concerns because the payloads themselves — such as `' OR 1=1--` for SQL injection — could potentially trigger unintended effects on poorly configured systems.

The ACM Code of Ethics (ACM, 2018) states that computing professionals should "avoid harm" (Principle 1.2) and "be honest and trustworthy" (Principle 1.3). SentinelAI addresses these principles through its consent mechanism and by providing remediation guidance alongside vulnerability reports. Rather than merely exposing weaknesses, the tool actively supports the fixing of identified issues through technology-specific code examples and best-practice recommendations.

### 3.3 Responsible Disclosure

The NCSC Vulnerability Disclosure Toolkit (NCSC, 2021) establishes a framework for responsible handling of discovered vulnerabilities. SentinelAI is designed to support this approach: scan results include detailed remediation instructions, encouraging users to fix vulnerabilities rather than exploit them. The tool is explicitly positioned as a defensive instrument, and this intent is reinforced through the user interface messaging and documentation.

### 3.4 Rate Limiting as Ethical Safeguard

A key ethical consideration is the potential for SentinelAI to inadvertently cause a denial-of-service condition on target servers through rapid, automated requests. In accordance with the BCS Code of Conduct requirement to "have due regard for public health, privacy, security and wellbeing of others" (BCS, 2022, Section 1), a rate limiting mechanism was implemented. The scanner introduces a configurable delay (default 0.5 seconds) between each outgoing request, ensuring that legitimate server operations are not disrupted during scanning.

### 3.5 AI Ethics

Where the Gemini API integration is active, an additional ethical dimension arises. AI models may produce inaccurate assessments (commonly termed "hallucinations"), potentially leading to false positives or, more dangerously, false negatives. The tool mitigates this by treating AI judgements as supplementary to heuristic analysis rather than as sole determinants, and by displaying confidence scores to maintain transparency about result reliability.

---

## 4. Legal Implications

### 4.1 Introduction

The legal landscape surrounding security testing tools is complex, with multiple overlapping legislative frameworks governing their use. SentinelAI's design incorporates several features specifically intended to support legal compliance.

### 4.2 Computer Misuse Act 1990

The Computer Misuse Act 1990 (CMA) is the primary UK legislation governing unauthorised access to computer systems. **Section 1** criminalises unauthorised access to computer material, carrying a maximum sentence of two years' imprisonment. **Section 3** addresses unauthorised acts intended to impair the operation of a computer, with penalties of up to ten years (Computer Misuse Act 1990, c.18).

SentinelAI's active scanning — sending crafted payloads to identify SQL injection and XSS vulnerabilities — could constitute an offence under Section 1 if performed without the system owner's authorisation. To address this, three safeguards were implemented:

1. **Consent mechanism**: Users must explicitly confirm authorisation via a mandatory checkbox before any scan can commence.
2. **Domain restriction**: The scanner automatically blocks scanning of sensitive domains including government (`.gov.uk`), healthcare (`nhs.uk`), law enforcement (`police.uk`), military (`.mil`), and major financial institutions. This prevents both accidental and deliberate scanning of critical national infrastructure.
3. **Legal disclaimer**: A prominent notice on the interface explicitly references the CMA 1990 and warns against unauthorised scanning.

### 4.3 General Data Protection Regulation (GDPR) and Data Protection Act 2018

The GDPR (Regulation (EU) 2016/679) and its UK implementation, the Data Protection Act 2018 (c.12), govern the processing of personal data. SentinelAI encounters personal data in two contexts:

First, the **Information Disclosure module** actively searches for email addresses exposed in page source code. Under Article 5(1)(c) of the GDPR, personal data processing must adhere to the principle of **data minimisation** — collecting only what is necessary for the specified purpose. To comply, discovered email addresses are automatically masked in scan results (e.g., `j***@company.com`), ensuring that the tool reports the existence of a vulnerability without unnecessarily exposing the personal data itself.

Second, scan results stored in the user's browser via `localStorage` may contain URLs and technical details about scanned systems. As this storage is entirely client-side with no server-side persistence, the data remains under the user's sole control, aligning with the GDPR principle of purpose limitation (Article 5(1)(b)). The audit log, maintained on the server, records only the target URL, timestamp, scan status, and finding count, and is automatically pruned to retain only the 100 most recent entries, further supporting data minimisation obligations.

### 4.4 Equality Act 2010

The Equality Act 2010 (c.15) requires that services be accessible to individuals with disabilities. While SentinelAI is a developer-focused tool rather than a consumer-facing service, accessibility considerations were incorporated into the interface design: high-contrast colour schemes, semantic HTML structure, and keyboard navigation support (the Enter key triggers scanning). Full WCAG 2.1 compliance (W3C, 2018) would be a priority for any future public deployment.

### 4.5 EU Cybersecurity Act and NIS2 Directive

The NIS2 Directive (Directive (EU) 2022/2555) establishes cybersecurity obligations for essential and important entities across the EU. SentinelAI supports compliance with these requirements by enabling organisations to conduct regular vulnerability assessments as mandated by Article 21 of NIS2. The tool's security header analysis and SSL/TLS verification directly address technical security measures specified in the directive.

---

## 5. Security Aspects

### 5.1 Introduction

As a security tool, SentinelAI must itself adhere to robust security practices. A vulnerability scanner that is itself insecure would be counterproductive and potentially dangerous.

### 5.2 Architecture Security

SentinelAI operates as a **local-only application**, running on `localhost` without exposing services to external networks. This architectural decision significantly reduces the attack surface compared to cloud-based alternatives. The NCSC Secure Development and Deployment Guidance (NCSC, 2023) recommends minimising the exposure of development and testing tools, and SentinelAI's local-only design aligns with this principle.

### 5.3 Secret Management

API credentials (specifically the Gemini API key) are stored in a `.env` file, which is excluded from version control via `.gitignore`. This follows the twelve-factor app methodology (Wiggins, 2017) for configuration management and prevents accidental exposure of secrets through source code repositories — a common vulnerability identified by GitGuardian (2024), which reported over 12 million hardcoded secrets detected in public repositories in 2023.

### 5.4 Audit Trail

An audit logging mechanism records every scan performed, capturing the timestamp, target URL, result status, and number of findings. This audit trail supports accountability and provides forensic evidence in the event of a dispute regarding authorised use. The log is limited to 100 entries through automatic pruning, balancing accountability requirements with data minimisation principles (ISO/IEC 27001:2022).

### 5.5 Known Limitations

Several security limitations are acknowledged. The CORS configuration in the FastAPI server uses a wildcard (`allow_origins=["*"]`), which in a production deployment should be restricted to specific trusted origins. Additionally, SSL certificate verification is disabled for outgoing scan requests (`verify=False`), as this is necessary to scan targets with self-signed or expired certificates — the very conditions the SSL/TLS module is designed to detect. The OWASP Testing Guide (OWASP, 2023) recognises this as an acceptable trade-off for security testing tools, provided it is documented.

### 5.6 User Wellbeing

SentinelAI provides clear, actionable remediation guidance for every identified vulnerability, reducing the stress and confusion that can accompany vulnerability reports. Each finding includes a confidence percentage, contextual analysis, and technology-specific code fixes, supporting informed decision-making rather than anxiety-driven responses.

---

## 6. Conclusion

The development of SentinelAI has required careful navigation of social, ethical, legal, and security considerations. As a dual-use technology, the tool carries inherent risks that have been mitigated through consent mechanisms, domain restrictions, rate limiting, legal disclaimers, data minimisation, and audit logging. These measures demonstrate that responsible development of security tools requires not only technical competence but also a thorough understanding of the professional and legal frameworks within which such tools operate.

---

## References

ACM (2018) *ACM Code of Ethics and Professional Conduct*. Available at: https://www.acm.org/code-of-ethics (Accessed: 25 April 2026).

BCS (2022) *BCS Code of Conduct*. Available at: https://www.bcs.org/membership-and-registrations/become-a-member/bcs-code-of-conduct/ (Accessed: 25 April 2026).

Computer Misuse Act 1990, c.18. Available at: https://www.legislation.gov.uk/ukpga/1990/18/contents (Accessed: 25 April 2026).

Data Protection Act 2018, c.12. Available at: https://www.legislation.gov.uk/ukpga/2018/12/contents (Accessed: 25 April 2026).

Dittrich, D. and Kenneally, E. (2012) *The Menlo Report: Ethical Principles Guiding Information and Communication Technology Research*. U.S. Department of Homeland Security.

Equality Act 2010, c.15. Available at: https://www.legislation.gov.uk/ukpga/2010/15/contents (Accessed: 25 April 2026).

General Data Protection Regulation (EU) 2016/679. Available at: https://gdpr-info.eu/ (Accessed: 25 April 2026).

GitGuardian (2024) *State of Secrets Sprawl 2024*. Available at: https://www.gitguardian.com/state-of-secrets-sprawl-report-2024 (Accessed: 25 April 2026).

IBM Security (2024) *Cost of a Data Breach Report 2024*. Available at: https://www.ibm.com/reports/data-breach (Accessed: 25 April 2026).

ISO/IEC 27001:2022 *Information security, cybersecurity and privacy protection — Information security management systems — Requirements*. Geneva: International Organization for Standardization.

NCSC (2021) *Vulnerability Disclosure Toolkit*. Available at: https://www.ncsc.gov.uk/information/vulnerability-disclosure-toolkit (Accessed: 25 April 2026).

NCSC (2023) *Secure Development and Deployment Guidance*. Available at: https://www.ncsc.gov.uk/collection/developers-collection (Accessed: 25 April 2026).

NCSC (2024) *Cyber Security Breaches Survey 2024*. Available at: https://www.gov.uk/government/statistics/cyber-security-breaches-survey-2024 (Accessed: 25 April 2026).

NIS2 Directive (EU) 2022/2555. Available at: https://eur-lex.europa.eu/ (Accessed: 25 April 2026).

OWASP (2021) *OWASP Top Ten 2021*. Available at: https://owasp.org/Top10/ (Accessed: 25 April 2026).

OWASP (2023) *OWASP Web Security Testing Guide v4.2*. Available at: https://owasp.org/www-project-web-security-testing-guide/ (Accessed: 25 April 2026).

Schneier, B. (2015) *Data and Goliath: The Hidden Battles to Collect Your Data and Control Your World*. New York: W.W. Norton & Company.

W3C (2018) *Web Content Accessibility Guidelines (WCAG) 2.1*. Available at: https://www.w3.org/TR/WCAG21/ (Accessed: 25 April 2026).

Wiggins, A. (2017) *The Twelve-Factor App*. Available at: https://12factor.net/ (Accessed: 25 April 2026).
