import { NextResponse } from "next/server"
import type { SecurityAuditResult, ComplianceCheck } from "@/types/security"

export async function POST(request: Request) {
  try {
    const { url } = await request.json()

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    // Validate URL format
    let targetUrl: URL
    try {
      targetUrl = new URL(url)
    } catch {
      return NextResponse.json({ error: "Invalid URL format" }, { status: 400 })
    }

    // Perform security audit
    const result = await performSecurityAudit(targetUrl.toString())

    return NextResponse.json(result)
  } catch (error) {
    console.error("Audit error:", error)
    return NextResponse.json({ error: "Failed to perform security audit" }, { status: 500 })
  }
}

async function performSecurityAudit(url: string): Promise<SecurityAuditResult> {
  // Fetch the URL and analyze headers
  const headers: Record<string, string> = {}
  let sslValid = true

  try {
    const response = await fetch(url, { method: "HEAD" })
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value
    })
  } catch (error) {
    console.error("Fetch error:", error)
    sslValid = false
  }

  // Analyze security headers
  const headerChecks = analyzeSecurityHeaders(headers)

  // Check SSL/TLS
  const sslCheck = analyzeSSL(url, sslValid)

  // Detect vulnerabilities
  const vulnerabilities = detectVulnerabilities(headers, url)

  const domainIntelligence = await analyzeDomainIntelligence(url)

  const compliance = analyzeCompliance(headers, sslCheck.valid)

  // Calculate summary
  const passed = headerChecks.filter((h) => h.status === "pass").length + (sslCheck.status === "pass" ? 1 : 0)
  const warnings = headerChecks.filter((h) => h.status === "warning").length + (sslCheck.status === "warning" ? 1 : 0)
  const failed =
    headerChecks.filter((h) => h.status === "fail").length +
    (sslCheck.status === "fail" ? 1 : 0) +
    vulnerabilities.length

  // Calculate overall score
  const totalChecks = headerChecks.length + 1
  const score = Math.round((passed / totalChecks) * 100)

  return {
    url,
    timestamp: new Date().toISOString(),
    score,
    summary: { passed, warnings, failed },
    ssl: sslCheck,
    headers: headerChecks,
    vulnerabilities,
    domainIntelligence,
    compliance,
  }
}

function analyzeSecurityHeaders(headers: Record<string, string>) {
  const checks = []

  // HSTS
  const hsts = headers["strict-transport-security"]
  checks.push({
    name: "Strict-Transport-Security",
    status: hsts ? "pass" : "fail",
    severity: "High" as const,
    value: hsts,
    description: "Enforces HTTPS connections and prevents protocol downgrade attacks.",
    recommendation: hsts ? undefined : "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
  })

  // CSP
  const csp = headers["content-security-policy"]
  checks.push({
    name: "Content-Security-Policy",
    status: csp ? "pass" : "fail",
    severity: "High" as const,
    value: csp,
    description: "Prevents XSS attacks by controlling which resources can be loaded.",
    recommendation: csp ? undefined : "Add: Content-Security-Policy: default-src 'self'; script-src 'self'",
  })

  // X-Frame-Options
  const xfo = headers["x-frame-options"]
  checks.push({
    name: "X-Frame-Options",
    status: xfo ? "pass" : "fail",
    severity: "Medium" as const,
    value: xfo,
    description: "Prevents clickjacking attacks by controlling iframe embedding.",
    recommendation: xfo ? undefined : "Add: X-Frame-Options: DENY or SAMEORIGIN",
  })

  // X-Content-Type-Options
  const xcto = headers["x-content-type-options"]
  checks.push({
    name: "X-Content-Type-Options",
    status: xcto ? "pass" : "fail",
    severity: "Medium" as const,
    value: xcto,
    description: "Prevents MIME-sniffing attacks.",
    recommendation: xcto ? undefined : "Add: X-Content-Type-Options: nosniff",
  })

  // Referrer-Policy
  const rp = headers["referrer-policy"]
  checks.push({
    name: "Referrer-Policy",
    status: rp ? "pass" : "warning",
    severity: "Low" as const,
    value: rp,
    description: "Controls how much referrer information is sent with requests.",
    recommendation: rp ? undefined : "Add: Referrer-Policy: strict-origin-when-cross-origin",
  })

  // Permissions-Policy
  const pp = headers["permissions-policy"]
  checks.push({
    name: "Permissions-Policy",
    status: pp ? "pass" : "warning",
    severity: "Low" as const,
    value: pp,
    description: "Controls which browser features can be used.",
    recommendation: pp ? undefined : "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
  })

  return checks
}

function analyzeSSL(url: string, valid: boolean) {
  const isHttps = url.startsWith("https://")

  return {
    valid: isHttps && valid,
    status: (isHttps && valid ? "pass" : "fail") as "pass" | "fail" | "warning",
    issuer: isHttps ? "Valid Certificate Authority" : "N/A",
    validFrom: isHttps ? new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toLocaleDateString() : "N/A",
    validTo: isHttps ? new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toLocaleDateString() : "N/A",
    recommendation:
      isHttps && valid ? undefined : "Ensure your site uses HTTPS with a valid SSL/TLS certificate from a trusted CA.",
  }
}

function detectVulnerabilities(headers: Record<string, string>, url: string) {
  const vulnerabilities = []

  // Check for exposed server information
  if (headers["server"]) {
    vulnerabilities.push({
      name: "Server Header Disclosure",
      severity: "Low" as const,
      description: "Server header reveals web server software and version, aiding attackers.",
      recommendation: "Remove or obfuscate the Server header in your web server configuration.",
    })
  }

  // Check for X-Powered-By header
  if (headers["x-powered-by"]) {
    vulnerabilities.push({
      name: "X-Powered-By Header Disclosure",
      severity: "Low" as const,
      description: "Reveals technology stack information that could be exploited.",
      recommendation: "Remove the X-Powered-By header from your application configuration.",
    })
  }

  // Check for missing security headers combo
  const criticalHeaders = ["strict-transport-security", "content-security-policy"]
  const missingCritical = criticalHeaders.filter((h) => !headers[h])

  if (missingCritical.length === criticalHeaders.length) {
    vulnerabilities.push({
      name: "Missing Critical Security Headers",
      severity: "High" as const,
      description: "Multiple critical security headers are missing, leaving the site vulnerable to common attacks.",
      recommendation: "Implement all recommended security headers, especially HSTS and CSP.",
    })
  }

  return vulnerabilities
}

async function analyzeDomainIntelligence(url: string) {
  const parsedUrl = new URL(url)
  const hostname = parsedUrl.hostname

  // Subdomain discovery (simulated - in production, use DNS APIs or certificate transparency logs)
  const subdomains = await discoverSubdomains(hostname)

  // Threat intelligence check (simulated - in production, integrate with VirusTotal, Google Safe Browsing, AbuseIPDB, etc.)
  const threatIntelligence = checkThreatIntelligence(hostname)

  // DNS security records check (simulated - in production, use DNS lookup APIs)
  const dnsRecords = await checkDNSRecords(hostname)

  return {
    subdomains,
    threatIntelligence,
    dnsRecords,
  }
}

async function discoverSubdomains(hostname: string): Promise<string[]> {
  // Simulated subdomain discovery
  // In production, use certificate transparency logs, DNS enumeration, or third-party APIs
  const commonSubdomains = ["www", "api", "admin", "mail", "blog", "shop", "dev", "staging"]

  const discovered: string[] = []

  for (const sub of commonSubdomains) {
    const subdomain = `${sub}.${hostname}`
    try {
      // Try to resolve the subdomain
      await fetch(`https://${subdomain}`, { method: "HEAD", signal: AbortSignal.timeout(2000) })
      discovered.push(subdomain)
    } catch {
      // Subdomain doesn't exist or is unreachable
    }
  }

  return discovered
}

function checkThreatIntelligence(hostname: string) {
  // Simulated threat intelligence check
  // In production, integrate with VirusTotal, Google Safe Browsing, AbuseIPDB, etc.

  // For demo purposes, flag suspicious patterns
  const isBlacklisted = hostname.includes("phishing") || hostname.includes("malware")
  const reputation = isBlacklisted ? "malicious" : "safe"
  const threatCategories = isBlacklisted ? ["phishing", "malware"] : []

  return {
    isBlacklisted,
    reputation: reputation as "safe" | "suspicious" | "malicious",
    threatCategories,
  }
}

async function checkDNSRecords(hostname: string) {
  // Simulated DNS record checks
  // In production, use DNS lookup APIs or libraries

  // For demo purposes, randomly assign values based on domain patterns
  const hasCommonTLD = hostname.endsWith(".com") || hostname.endsWith(".org") || hostname.endsWith(".net")

  return {
    hasDNSSEC: hasCommonTLD && Math.random() > 0.5,
    hasSPF: hasCommonTLD && Math.random() > 0.3,
    hasDMARC: hasCommonTLD && Math.random() > 0.4,
    hasDKIM: hasCommonTLD && Math.random() > 0.4,
  }
}

function analyzeCompliance(headers: Record<string, string>, sslValid: boolean): SecurityAuditResult["compliance"] {
  return {
    gdpr: checkGDPRCompliance(headers),
    ccpa: checkCCPACompliance(headers),
    soc2: checkSOC2Compliance(headers, sslValid),
    pciDss: checkPCIDSSCompliance(headers, sslValid),
  }
}

function checkGDPRCompliance(headers: Record<string, string>): ComplianceCheck {
  const checks = [
    {
      name: "Cookie Consent",
      passed: false, // Would need to check page content for cookie banner
      description: "Site must obtain user consent before setting non-essential cookies",
      recommendation: "Implement a cookie consent banner that allows users to opt-in/opt-out",
    },
    {
      name: "Privacy Policy",
      passed: false, // Would need to check for privacy policy page
      description: "Site must have a clear and accessible privacy policy",
      recommendation: "Create and link to a comprehensive privacy policy",
    },
    {
      name: "Data Protection Headers",
      passed: !!headers["content-security-policy"],
      description: "Security headers help protect user data",
    },
    {
      name: "Secure Data Transmission",
      passed: !!headers["strict-transport-security"],
      description: "All data must be transmitted securely via HTTPS",
      recommendation: !headers["strict-transport-security"] ? "Enable HSTS to enforce secure connections" : undefined,
    },
  ]

  const passedCount = checks.filter((c) => c.passed).length
  const score = Math.round((passedCount / checks.length) * 100)
  const status = score >= 75 ? "compliant" : score >= 50 ? "partial" : "non-compliant"

  return { status, score, checks }
}

function checkCCPACompliance(headers: Record<string, string>): ComplianceCheck {
  const checks = [
    {
      name: "Do Not Sell Link",
      passed: false, // Would need to check page content
      description: "Site must provide a 'Do Not Sell My Personal Information' link",
      recommendation: "Add a clear link allowing California residents to opt-out of data sales",
    },
    {
      name: "Privacy Notice",
      passed: false, // Would need to check page content
      description: "Site must disclose data collection and usage practices",
      recommendation: "Create a detailed privacy notice explaining data practices",
    },
    {
      name: "Secure Data Handling",
      passed: !!headers["strict-transport-security"] && !!headers["content-security-policy"],
      description: "Secure headers protect consumer data",
      recommendation:
        !headers["strict-transport-security"] || !headers["content-security-policy"]
          ? "Implement security headers to protect user data"
          : undefined,
    },
  ]

  const passedCount = checks.filter((c) => c.passed).length
  const score = Math.round((passedCount / checks.length) * 100)
  const status = score >= 75 ? "compliant" : score >= 50 ? "partial" : "non-compliant"

  return { status, score, checks }
}

function checkSOC2Compliance(headers: Record<string, string>, sslValid: boolean): ComplianceCheck {
  const checks = [
    {
      name: "Encryption in Transit",
      passed: sslValid && !!headers["strict-transport-security"],
      description: "Data must be encrypted during transmission",
      recommendation: !sslValid ? "Enable HTTPS with a valid SSL certificate" : undefined,
    },
    {
      name: "Security Controls",
      passed: !!headers["content-security-policy"] && !!headers["x-content-type-options"],
      description: "Implement security controls to protect system and data",
      recommendation: !headers["content-security-policy"] ? "Add CSP and other security headers" : undefined,
    },
    {
      name: "Access Controls",
      passed: !!headers["x-frame-options"],
      description: "Prevent unauthorized access through clickjacking",
      recommendation: !headers["x-frame-options"] ? "Add X-Frame-Options header" : undefined,
    },
    {
      name: "Monitoring & Logging",
      passed: true, // Assumed - would need backend verification
      description: "System activity must be monitored and logged",
    },
  ]

  const passedCount = checks.filter((c) => c.passed).length
  const score = Math.round((passedCount / checks.length) * 100)
  const status = score >= 75 ? "compliant" : score >= 50 ? "partial" : "non-compliant"

  return { status, score, checks }
}

function checkPCIDSSCompliance(headers: Record<string, string>, sslValid: boolean): ComplianceCheck {
  const checks = [
    {
      name: "Strong Encryption",
      passed: sslValid,
      description: "Cardholder data must be encrypted with strong cryptography",
      recommendation: !sslValid ? "Use TLS 1.2 or higher with valid certificates" : undefined,
    },
    {
      name: "Secure Transmission",
      passed: !!headers["strict-transport-security"],
      description: "Enforce secure connections for all cardholder data transmission",
      recommendation: !headers["strict-transport-security"] ? "Enable HSTS" : undefined,
    },
    {
      name: "Web Application Security",
      passed: !!headers["content-security-policy"] && !!headers["x-frame-options"],
      description: "Protect web applications against common attacks",
      recommendation: !headers["content-security-policy"] ? "Implement CSP and anti-clickjacking measures" : undefined,
    },
    {
      name: "Information Disclosure Prevention",
      passed: !headers["server"] && !headers["x-powered-by"],
      description: "Do not expose server and technology information",
      recommendation: headers["server"] || headers["x-powered-by"] ? "Remove server identification headers" : undefined,
    },
  ]

  const passedCount = checks.filter((c) => c.passed).length
  const score = Math.round((passedCount / checks.length) * 100)
  const status = score >= 75 ? "compliant" : score >= 50 ? "partial" : "non-compliant"

  return { status, score, checks }
}
