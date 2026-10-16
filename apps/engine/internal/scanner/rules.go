package scanner

// DefaultQuellRulesYAML contains embedded high-recall OWASP Top 10 rules
// tailored for Node.js, TypeScript, Python, and Go to feed candidates into
// Quell's AST Chunker and Contextual AI Triage.
const DefaultQuellRulesYAML = `
rules:
  - id: quell.node.sqli.raw-query-concatenation
    languages: [javascript, typescript]
    severity: ERROR
    message: "Potential SQL Injection detected: raw query concatenation with user-controllable input."
    patterns:
      - pattern-either:
          - pattern: |
              $Q = "..." + $INPUT + "...";
              ...
              $DB.query($Q, ...);
          - pattern: |
              $DB.query("..." + $INPUT + "...", ...);
          - pattern: |
              $Q = ` + "`" + `...${$INPUT}...` + "`" + `;
              ...
              $DB.query($Q, ...);
          - pattern: |
              $DB.query(` + "`" + `...${$INPUT}...` + "`" + `, ...);
    metadata:
      cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
      owasp: "A03:2021 - Injection"
      vulnerability_type: "SQL_INJECTION"

  - id: quell.node.auth.missing-tenant-validation-idor
    languages: [javascript, typescript]
    severity: WARNING
    message: "Suspect Broken Object Level Authorization (IDOR): Object fetched directly by user parameter without organizational tenant scope."
    patterns:
      - pattern-either:
          - pattern: |
              async function $HANDLER(req, res, ...) {
                ...
                const $ID = req.params.$PARAM;
                ...
                $DB.query($QUERY, [$ID]);
                ...
              }
          - pattern: |
              async function $HANDLER(req, res, ...) {
                ...
                $DB.query($QUERY, [req.params.$PARAM]);
                ...
              }
    metadata:
      cwe: "CWE-639: Authorization Bypass Through User-Controlled Key"
      owasp: "A01:2021 - Broken Access Control"
      vulnerability_type: "IDOR"

  - id: quell.secrets.hardcoded-credentials
    languages: [javascript, typescript, python, go]
    severity: ERROR
    message: "Potential hardcoded secret or API credential detected in source code."
    patterns:
      - pattern-regex: "(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|password)\\s*[:=]\\s*['\"][A-Za-z0-9_\\-]{16,}['\"]"
    metadata:
      cwe: "CWE-798: Use of Hard-coded Credentials"
      owasp: "A07:2021 - Identification and Authentication Failures"
      vulnerability_type: "HARDCODED_SECRET"

  - id: quell.node.xss.unescaped-direct-send
    languages: [javascript, typescript]
    severity: WARNING
    message: "Potential Reflected XSS: Direct user input echoed to response body without encoding."
    patterns:
      - pattern-either:
          - pattern: res.send("..." + req.query.$PARAM + "...")
          - pattern: res.write("..." + req.query.$PARAM + "...")
    metadata:
      cwe: "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
      owasp: "A03:2021 - Injection"
      vulnerability_type: "XSS"
`
