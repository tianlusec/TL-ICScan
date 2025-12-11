# Security Policy

[中文版](SECURITY.md)

## Supported Versions

We provide security update support for the following versions:

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| 0.6.x   | :white_check_mark: | Current version, fully supported |
| 0.5.x   | :white_check_mark: | Maintained, critical security fixes |
| < 0.5.0 | :x:                | No longer supported, please upgrade |

**Recommendation**: Always use the latest stable version for best security and features.

## Reporting a Vulnerability

### Important Notice

If you discover a security vulnerability in this project, please **DO NOT** disclose it publicly in GitHub Issues. We follow a responsible disclosure process to protect user security.

### Reporting Methods

Please contact us via one of the following methods:

1. **GitHub Security Advisories** (Recommended)
   - Visit the project's [Security Advisories](https://github.com/tianlusec/TL-ICScan/security/advisories)
   - Click "Report a vulnerability"
   - Fill in detailed information

2. **Email**
   - Send to: security@tianlulab.com
   - Subject format: `[SECURITY] TL-ICScan - Brief Description`
   - Use encrypted email if you have PGP key

3. **Private Issue**
   - Create a private security report on GitHub

### Report Should Include

To help us quickly understand and fix the issue, please include in your report:

- **Vulnerability Type**: e.g., SQL injection, XSS, path traversal, etc.
- **Affected Scope**: Which versions are affected
- **Reproduction Steps**: Detailed step-by-step instructions
- **Proof of Concept**: PoC code or screenshots (if applicable)
- **Impact Assessment**: Your assessment of severity and potential impact
- **Fix Suggestions**: If you have a fix proposal (optional)
- **Contact Information**: For follow-up communication

### Response Timeline

We commit to:

- **Within 48 hours**: Acknowledge receipt of report
- **Within 7 days**: Provide initial assessment and fix plan
- **Within 30 days**: Release security patch (depending on severity)
- **After fix**: Coordinate disclosure timeline with you

### Security Update Release

Security updates will be released through:

- GitHub Security Advisories
- GitHub Releases (marked as security update)
- Project README changelog

## Security Scope

### In Scope

The security scope of this project includes:

- ✅ **Core Engine** (`tianlu-intel-core`)
  - SQL query construction
  - File operations
  - Command-line argument parsing

- ✅ **Collectors** (`tianlu_intel_collectors`)
  - API call security
  - Data parsing logic
  - Input validation
  - Credential management

- ✅ **Web UI** (`web_ui`)
  - User input validation
  - XSS protection
  - CSRF protection
  - Session management

- ✅ **Data Storage**
  - Database security
  - File permissions
  - Sensitive information protection

### Out of Scope

The following are not considered security vulnerabilities of this project:

- ❌ **Third-party Data Sources**: The vulnerability intelligence (CVE data) collected by this project contains public vulnerability information
- ❌ **Dependency Vulnerabilities**: Unless directly affecting this project's security
- ❌ **Configuration Errors**: Security issues caused by improper user configuration
- ❌ **Social Engineering**: Phishing or fraud targeting users

## Security Best Practices

### For Users

1. **Keep Updated**: Always use the latest version
2. **Secure Configuration**:
   - Don't commit API keys to public repositories
   - Use environment variables for sensitive information
   - Restrict database file access permissions
3. **Network Security**:
   - Run in trusted network environments
   - Use firewall to protect Web UI ports
4. **Regular Audits**: Check log files and database contents

### For Developers

1. **Code Review**: All PRs must undergo security review
2. **Dependency Management**: Regularly update dependencies and check for known vulnerabilities
3. **Input Validation**: Strictly validate all external inputs
4. **Least Privilege**: Follow the principle of least privilege
5. **Security Testing**: Write security-related test cases

## Known Security Considerations

### Local Database

- Database file (`tianlu_intel_v2.db`) is stored locally
- Recommend setting appropriate file permissions (owner read/write only)
- Does not contain user credentials or sensitive personal information

### API Key Management

- Use environment variables to store API keys
- Don't hardcode keys in code or configuration files
- Regularly rotate API keys

### Web UI Access

- Default binding to localhost (127.0.0.1)
- For remote access, use reverse proxy and HTTPS
- Consider adding authentication mechanism

## Acknowledgments

We thank the following security researchers for responsible disclosure:

<!-- Security researcher list will be shown here -->

*No public security reports yet.*

## Contact

- **Security Email**: security@tianlulab.com
- **Project Homepage**: https://github.com/tianlusec/TL-ICScan
- **Security Advisories**: https://github.com/tianlusec/TL-ICScan/security/advisories

---

**Thank you for helping protect TL-ICScan and our users!**
