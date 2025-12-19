export interface SecurityAuditResult {
  url: string
  timestamp: string
  score: number
  summary: {
    passed: number
    warnings: number
    failed: number
  }
  ssl: {
    valid: boolean
    status: "pass" | "fail" | "warning"
    issuer: string
    validFrom: string
    validTo: string
    recommendation?: string
  }
  headers: Array<{
    name: string
    status: "pass" | "fail" | "warning"
    severity: "Low" | "Medium" | "High"
    value?: string
    description: string
    recommendation?: string
  }>
  vulnerabilities: Array<{
    name: string
    severity: "Low" | "Medium" | "High"
    description: string
    recommendation: string
  }>
  domainIntelligence: {
    subdomains: string[]
    threatIntelligence: {
      isBlacklisted: boolean
      reputation: "safe" | "suspicious" | "malicious"
      threatCategories: string[]
    }
    dnsRecords: {
      hasDNSSEC: boolean
      hasSPF: boolean
      hasDMARC: boolean
      hasDKIM: boolean
    }
  }
  compliance: {
    gdpr: ComplianceCheck
    ccpa: ComplianceCheck
    soc2: ComplianceCheck
    pciDss: ComplianceCheck
  }
}

export interface ComplianceCheck {
  status: "compliant" | "partial" | "non-compliant"
  score: number
  checks: Array<{
    name: string
    passed: boolean
    description: string
    recommendation?: string
  }>
}
