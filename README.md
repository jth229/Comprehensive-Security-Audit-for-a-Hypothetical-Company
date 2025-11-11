# Comprehensive-Security-Audit-for-a-Hypothetical-Company
A detailed, security audit for a hypothetical company. 


Comprehensive Security Audit for a Hypothetical Company


Company Background

	The hypothetical company for this assignment, Bookster, is based on an online book store, making it an E-Commerce business. There are approximately 250 employees and the company’s infrastructure is cloud-based.With the company being e-commerce, some of the key operations within this organization include: online book sales, customer management, inventory & supply chain, payment processing, customer support, and marketing & analytics. This list of operations is relatively large, which means that the types and amount of data it handles will vary as well. Some of the types of data that this company handles on a daily basis include: customer data, payment data, business data, and digital assets. The purpose of this assignment will be to create a network diagram with proper security protocols in place, while creating a proper IRP and Security Policy to ensure that Bookster’s data remain safe.


Network and System Security

	The network diagram that I created for Bookster is pictured on the previous page. First, it lists all of the end-users, both internal employees and external users. For all of the employees of Bookster, a VPN was implemented for them to have access to company resources. Non-employees of Bookster are required to successfully get through the Web Application Firewall, better protecting the company’s resources from external threat actors. In addition, all external user traffic goes through another firewall and all incoming traffic is monitored through the use of both an IPS and IDS. A load-balancer was also placed in the web tier of the cloud environment to help distribute incoming traffic and help reduce processing delays in the servers. 

Application and Web Security

	As an online book store, Bookster uses an online website for their customers to access their online inventory of books that they offer. They also offer a mobile app available on both Android and iOS devices, allowing customers to read e-books on their phones. On the company side, they store all company data on a cloud server. With no on-premise servers, Bookster is vulnerable to outside threat actors. I have analyzed the OWASP Top 10 and how these apps could face similar security vulnerabilities. 

Broken Access Control
Vulnerabilities: With their online website, there is a possibility that customers could gain access to other users’ reviews and orders. There is also the vulnerability of an employee escalating access privileges in the CRM.
Resolution: Implement role-based access control, enforce least privilege across all systems, and apply authorization checks on server-side.
Cryptographic Failures
Vulnerabilities: Payroll data, PII, and credit card data stored by Bookster are at risk of exposure if they do not use strong encryption. 
Resolution: Encrypt sensitive data at rest (use AES-256), use TLS 1.3 for all data in-transit, and never store CVV numbers from customer’s credit/debit card.
Injection
Vulnerabilities: Bookster faces the possibility of SQL injection on their inventory database and review database. They also face the risk of noSQL injection on their search queries.
Resolution: Constantly ensure input validation and sanitization, apply and enforce web application firewall rules for SQLi patterns, use prepared statements and ORM frameworks.
Insecure Design
Vulnerabilities: There is the possibility for weak session management and the lack of rate limiting could potentially lead to account takeover or DoS.
Resolution: Apply threat modeling during design, implement rate limiting, CAPTCHA, and account lockouts, and adopt secure design patterns for mobile authentication and payment flows.
Security Misconfiguration
Vulnerabilities: Since Bookster primarily operates via a cloud, there are always vulnerabilities within the cloud configuration, such as open S3 buckets or exposed admin panels. 
Resolution: Disable directory listing and default admin accounts, ensure regular and constant cloud configuration audits (use CIS Benchmarks), and use hardened VM images and container baselines.
Vulnerable and Outdated Components
Vulnerabilities: There is the possibility that Bookster uses outdated e-reader libraries as well as having old CRM plugins.
Resolution: Use automated dependency scans, maintain Software Bill of Materials, and use a patch management policy with defined SLA’s.
Identification and Authentication Failures
Vulnerabilities: As with any company, Bookster could potentially have a weak password policy in place, as well as no usage of a Multi-Factor Authenticator, which could lead to credential stuffing.
Resolution: Require an MFA for all admin, employee, and customer logins, enforce password complexity and use secure reset flows.
Software and Data Integrity Failures
Vulnerabilities: Mobile application updates could be tampered with and there is the risk for unverified plugins.
Resolution: Enforce CI/CD pipeline checks, use code signing for mobile apps, and verify package integrity with checksums and signatures.
Security Logging and Monitoring Failures
Vulnerabilities: There is a possibility for breaches to not be detected, which could then lead to attackers exfiltrating customer data silently, without detection.
Resolution: Incorporate and use a centralized SIEM (such as Splunk or Azure Sentinel), enable alerting for privilege escalation attempts, and log all authentication failures and unusual API activity.
Server Side Request Forgery 
Vulnerabilities: There is a chance that an attacker could abuse Bookster’s APIs to pivot into their cloud services.
Resolution: Block all direct external calls from application servers (unless they are explicitly needed), enforce allow-list based outbound connections, and use network segmentation to isolate sensitive resources.


Cryptography

	Secure communications are important for Bookster, because their website, mobile applications and APIs exchange sensitive data (such as credit card numbers, addresses, and payroll records). If there is no use of strong encryption in transit, attackers could intercept or manipulate traffic. With the sensitive data at rest (secure storage) in cloud databases and storage buckets, weak/no encryption could lead to this data being compromised, leading to potential identity theft, financial fraud, and regulatory penalties. Key Management is critical for Bookster because if they mishandle their keys, attackers could decrypt data even if their databases are encrypted. For their website and mobile apps, I would recommend that they enforce HTTPS with TLS 1.3 + HSTS, secure cookies and tokens and use certification pinning in the apps. With their databases and storage, Bookster should turn on encryption at rest (AES-256), tokenize customers’ credit card data via PCI-compliant provider, and encrypt reviews, orders, and employee data fields containing PII. For key management, Bookster should adopt a KMS solution (Azure Key Vault), store API tokens in a vault, and implement the rotation of keys periodically. In terms of governance, the admin at Bookster should define encryption policies, train developers not to bypass encryption, and run compliance checks against PCI DSS and GDPR/CCPA. These strict methods to follow for data encryption will allow a much more secured network and system. 

Incident Response and Risk Management

Incident Response Plan:

Preparation
Policies and Playbooks
Bookster should incorporate the following security policies:
Data Handling
Access Control
Mobile Application Security
Implement and maintain IR playbooks for different threats such as:
DDoS Attacks
Phishing
Data Breach
Ransomware
Training
Continuous security awareness programs for phishing and social engineering attacks should be conducted and required for employees on a quarterly basis.
Bookster Administration would benefit from running incident response tabletop programs on a quarterly basis.
Tools
Use SIEM tools for centralized logging (Splunk or Azure Sentinel recommended).
Use both an IDS and IPS to monitor, alert and prevent intrusions (Suritica, Snort or any cloud-native equivalents will suffice).
Ensure that all laptops and servers connected to Bookster’s network are protected with an Endpoint Detection and Response software.
It is also crucial for Bookster to use a Web Application Firewall and implement a form of DDoS protection (suggestions would be Cloudfare, AWS Shield, or Azure Front Door).
Identification
Sources of Detection
Any signs of abnormal login attempts, data exfiltration, and DDoS patterns shall trigger an alert from the selected SIEM tool.
Injection attempts on any of Bookster’s website and mobile APIs will result in a detection from the selected IDS/IPS.
Payment transactions should be constantly audited and monitored to indicate any potential fraudulent activities.
Containment
Short-term:
Isolate the compromised systems by detaching from production networks (remove from the load balancer and revoke the public IP). Since Bookster operates on a cloud environment, the instance should be isolated to a quarantined subnet or security group. Access credentials should then be blocked and automated scaling should be disabled.
Long-term:
Any vulnerabilities exploited within the network should be patched. In addition, sensitive services should be moved behind an isolated VPN or a zero-trust access subnet.
Eradication
Remove malware or injected code from both the web and mobile applications.
All compromised credentials should be reset and enforce MFA.
Revoke or rotate the leaked API keys.
Recovery
All services from Bookster should be restored from clean, encrypted backups.
Affected systems should then be gradually reintroduced into production.
Systems should then be monitored closely for any possible occurrence of reinfections or persistent threats.
Lessons Learned 
Once systems and data are recovered and restored, Bookster would benefit from conducting post incident reviews.
Upon completion of these post-incident reviews, admin should collaborate with IT professionals so that they can update security protocols and their IR playbooks.
In addition to reporting to regulators and customers upon initial attack, Bookster admin should make sure to communicate and report to the same groups post-accident if it is required by law (PCI DSS, GDPR breach notifications within 72 hours of the incident).

Risk Management 

Risk Identification
Technical Risks: 
With their reliance on a cloud and with their website and mobile apps, Bookster is prone to data breaches via SQL injection, XSS, and API abuse.
In addition to their website vulnerabilities, DDoS attacks could occur, resulting in a disruption of their online store.
APIs within their mobile applications are also a vulnerability.
Operational Risks:
With insider threats as a constant potential to occur, Bookster is prone to an employee misusing access.
Since they operate on a cloud, their cloud systems are prone to misconfiguration, leading to data exposure.
Compliance Risks:
Given the nature of their business, PCI DSS violations are a possibility if payment information mishandling were to occur.
GDPR/CCPA fines could also occur if Bookster were to mishandle employee PII.
Business Risks:
If a data breach were to occur, Bookster could lose customers due to a mistrust, resulting in reputational damages and potential lawsuits.
In the event of an incident, Bookster could lose revenue if they were to experience downtime.
Risk Assessment
After creating and analyzing a Risk Matrix, Bookster should classify their vulnerabilities based on the level of each risk/vulnerability.
High-Risk: A data breach could result in customer and employee PII being compromised.
Medium-Risk: Due to their online presence with their website, Bookster could face DDoS attacks, resulting in temporary outage of their website.
Low-Risk: Employees falling victim to a phishing email.
Risk Mitigation
Preventive Controls:
Ensure that encryption is used for all data, whether in-transit or at rest (use AES-256 and TLS 1.3).
Require that all admin and employees are subject to the use of MFA when attempting to log on to company systems.
Implement regular vulnerability scanning and conduct penetration tests often.
Detective Controls:
The use of SIEM log correlation and anomaly detection through both an IDS and an IPS.
Ensure fraud monitoring for any unusual purchases.
Corrective Controls:
Use incident response playbooks.
Create and use a Disaster Recovery Plan (DRP) and make sure that it defines the RTO/RPO.
Risk Transfer
Bookster would benefit from purchasing a cybersecurity insurance policy that would cover data breaches, fines, and downtimes.
They would also benefit from outsourcing their payment handling to PCI DSS-compliant third-party providers (such as Stripe or Ayden).
Risk Acceptance
Bookster should accept low-probability risks where the mitigation cost is greater than the potential loss (such as zero-days with no patch available).
Continuous Improvement
Admin at Bookster should ensure that they conduct risk reviews every quarter.
They could also implement regular red team vs blue team exercises.
Ensure that there is continuous Cloud Security Posture Management (CSPM).

Cloud and Mobile Security

	Since Bookster primarily operates on a cloud platform and with the use of their mobile applications, they must ensure the use of secure configurations. On the mobile side, there are a few vulnerabilities that Bookster could face. First, their mobile applications could have some vulnerabilities such as poor coding practices, which could lead to reverse engineering, insecure APIs or tampered APK/IPA files. To mitigate this, they should use secure coding standards based on the OWASP Top 10, apply certificate pinning, and sign and verify all application updates. Next, in the case that a device should become lost or stolen, Bookster can protect their systems by enforcing MDM policies through Intune and require both strong PIN and biometric authentication. With the potential of credentials being exposed if a customer or an employee were using public Wi-Fi, they should enforce TLS 1.3 from end-to-end and also use a VPN. In the event that an employee’s personal device were to introduce some form of malware or non-compliant apps, Bookster would benefit from deploying MDM across all devices to enforce compliance and use MAM app protection policies for Outlook/CRM access. 

	In regard to the cloud side of their company network, Bookster could experience a few risks and vulnerabilities. Misconfigured storage could lead to S3 buckets being open, weak access controls, or compromised credentials lead to the exposure of both employee and customer PII and customer payment information. To mitigate this, Bookster should enforce IAM policies with least privilege, use MFA, and require that all data in transit and at rest be encrypted. Additional cloud misconfigurations could be insecure defaults, unpatched virtual machines, or exposed management systems. The use of CIS Benchmarks or CSPM tools, running automated configuration scans, and applying patch management SLA’s for VMs and containers would be appropriate methods to mitigate this. Since Bookster is prone to DDoS attacks, they should deploy DDoS protection (such as Cloudfare or Azure DDoS Protection), use CDN caching to to absorb any spikes in network traffic, and implement rate limiting and throttling at all API gateways. 

	With secure configuration best practices, the company will find themselves in a much more comfortable and manageable position. For their cloud security, they need to make sure they are hardening configurations with CIS Benchmarks, encrypt data everywhere, segment networks and isolate workloads, and use automated compliance checks. In regards to their mobile security, Bookster admin should enforce encryption, lock screens and MFA on all mobile devices, ensure compliance with MDM and MAM policies, and secure API communications with TLS, OAuth2.0, and token expiration. This will lead to a very organized and strengthened network for Bookster.

Security Policies and Standards

Bookster

The purpose of this security policy is to establish a standard for the protection of Bookster's information resources. This policy aims to protect our employees, partners, and the company from illegal or damaging actions, either intentionally or unintentionally. Administration will ensure consistent and strict monitoring of these policies as they are enforced on all employees. 
This policy applies to all employees of Bookster, contractors, consultants, temporaries and other workers at Bookster, including all personnel affiliated with third-parties. The acceptable use policy defines what actions are permitted when using Bookster’s IT systems and data. Under no circumstance shall an employee ever use or access Bookster’s systems and data on an unsecured mobile device. Access control policies help ensure that data and system information are only accessible to qualified employees. To enforce this, Bookster will practice least-privilege and role-based access controls. Bookster will require that all employees and administrators are verified through MFA and that all accounts will be reviewed quarterly, to ensure that any unused privileges can be removed. The password policy will ensure that all employee and administrator accounts comply with complex and long password policies, as well as ensuring password expiration every 90 calendar days to prevent credential theft. 
The asset management policy will outline how Bookster maintains an inventory of all company assets. Data classification for all assets shall be categorized and classified as either; Public, Internal, Confidential, or Restricted. Data that is classified under either Confidential or Restricted must always remain encrypted in-transit and at rest. Cryptography policies will ensure the best security for concealing data from threats. All data at rest shall be encrypted using AES-256, while all data in transit shall be encrypted using TLS 1.3. All encrypted keys will be managed through Azure Key Vault. 
Operations security policies will help reinforce and strengthen Bookster’s network. Bookster will apply patch management SLAs within 48 hours. SIEM monitoring for logs shall be enabled and malicious traffic will be dealt with through the use of a Web Application Firewall and both IDS/IPS tools. 
Supplier relationship policies shall pertain to all third-party vendors (such as our payment processors). This will ensure that our third-party vendors stay compliant with PCI DSS protocols. All contracts with third-parties must include security SLAs and data protection clauses. Failure to comply with can lead to the release of a third-party. 
Bookster has implemented an incident response plan to effectively respond to security incidents and mitigate their impact. It is the responsibility of the CISO to overall manage and enforce these policies. It is the responsibility of the IT team to implement these security measures and maintain the security of our IT systems. All employees must comply with this security policy and report any security incidents that they identify.
Any employee found to have violated this policy may be subject to disciplinary action, up to and including termination of employment. This policy will be reviewed and updated annually as needed based on changes to our business, technology, or the regulatory environment.
	Upon completion of full understanding and acceptance of these policies, please sign, print and date below:


Employee Signature:                                   Full Name (Print):                        Date: 



