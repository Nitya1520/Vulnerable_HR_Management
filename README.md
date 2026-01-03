 #**Vulnerable HR Management System (Educational Project)**

 Important Security Disclaimer

This repository contains an intentionally vulnerable web application developed strictly for educational and learning purposes.

This application is NOT secure
This application is NOT production-ready
Do NOT deploy with real user data

The objective of this project is to identify, exploit, and remediate common web application security vulnerabilities in a controlled environment.

⸻
 Project Purpose

This project helps learners to:
	•	Understand real-world web vulnerabilities
	•	Practice secure code review
	•	Perform SAST & DAST security testing
	•	Learn secure coding and remediation
	•	Explore OWASP Top 10 risks

Suitable for:
	•	Academic projects
	•	Cybersecurity labs
	•	Security demonstrations
⸻
Known Vulnerabilities with Severity Rating

Severity is based on OWASP impact + exploitability (CVSS-style approximation)

Category	Vulnerability	Severity
Secrets Management	Exposed .env secrets (JWT, DB URI)	🔴 Critical
Authentication	Weak JWT secret	🔴 Critical
Authentication	JWT returned in response body	🟠 High
Authentication	No account lockout / MFA	🟠 High
API Security	Open CORS policy	🟠 High
Input Validation	No input validation / sanitization	🔴 Critical
Injection	NoSQL injection risk	🔴 Critical
Data Protection	Plaintext PII storage (PAN, UAN, bank)	🔴 Critical
Transport Security	No HTTPS enforcement	🟠 High
CSRF	Missing CSRF protection	🟠 High
Hardening	Missing security headers	🟡 Medium
Logging	Verbose error messages	🟡 Medium
Abuse Prevention	No rate limiting	🟠 High
Request Handling	Large request body limits	🟡 Medium
Dependencies	No dependency scanning	🟡 Medium
Monitoring	No audit / security logging	🟡 Medium

⸻
 How to Fix These Vulnerabilities (Remediation Guide)
 Secrets & Configuration — Critical
	•	Never commit .env files
	•	Rotate leaked secrets immediately
	•	Use high-entropy secrets (32+ chars)
	•	Enable GitHub secret scanning / Gitleaks
Authentication & JWT — Critical / High
	•	Store JWT in HTTP-only Secure cookies
	•	Use consistent token expiry
	•	Implement refresh tokens
	•	Add account lockout after failed attempts
	•	Support session revocation & logout
	•	Add MFA for privileged users
 Rate Limiting & Brute-Force — High
	•	Apply rate limiting (express-rate-limit)
	•	Throttle login attempts
	•	Add CAPTCHA for sensitive endpoints
Input Validation & Injection — Critical
	•	Validate all inputs (Joi, Zod, express-validator)
	•	Sanitize payloads
	•	Block MongoDB operators ($ne, $gt, $where)
	•	Prefer allow-lists over deny-lists
CORS, CSRF & Transport — High
	•	Restrict CORS to trusted origins
	•	Implement CSRF protection (csurf)
	•	Enforce HTTPS only
	•	Set cookies:
	•	HttpOnly
	•	Secure
	•	SameSite=Strict
 Security Headers — Medium
	•	Use helmet
	•	Configure CSP, X-Frame-Options
	•	Disable stack traces in production
 Data Protection — Critical
	•	Encrypt sensitive data at rest
	•	Mask PII in responses
	•	Minimize stored sensitive data
 Dependency & CI Security — Medium
	•	Run npm audit
	•	Enable Dependabot
	•	Integrate Snyk
	•	Pin dependency versions
 Logging & Monitoring — Medium
	•	Implement centralized logging
	•	Audit auth & privileged actions
	•	Never log secrets or PII
	•	Enable alerts for anomalies

⸻
Recommended Security Tools
	•	Secret Scanning: Gitleaks, TruffleHog
	•	SAST: Semgrep, ESLint security plugins
	•	DAST: OWASP ZAP, Burp Suite
	•	Dependency Scanning: npm audit, Snyk
	•	Manual Testing: curl, Postman, fuzzing

⸻
 Usage Warning

This project is intentionally insecure by design.

 Do NOT deploy to production
 Do NOT expose publicly
 Do NOT use real credentials

⸻
 Learning Outcomes

By working on this repository, learners will:
	•	Identify OWASP Top 10 vulnerabilities
	•	Understand risk severity and impact
	•	Practice real-world remediation
	•	Compare vulnerable vs secure designs

⸻
 Final Note

This repository exists only for educational purposes.
Any real-world usage requires complete security hardening.

⸻
 Status

Intentionally Vulnerable — For Learning & Security Practice Only

⸻
