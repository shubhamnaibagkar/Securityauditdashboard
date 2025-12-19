"use client"

import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import type { SecurityAuditResult } from "@/types/security"

interface SecurityResultsProps {
  results: SecurityAuditResult
}

export function SecurityResults({ results }: SecurityResultsProps) {
  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-500"
    if (score >= 60) return "text-yellow-500"
    return "text-red-500"
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "high":
        return "bg-red-500/10 text-red-500 border-red-500/20"
      case "medium":
        return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20"
      case "low":
        return "bg-blue-500/10 text-blue-500 border-blue-500/20"
      default:
        return "bg-muted text-muted-foreground"
    }
  }

  const getStatusIcon = (status: "pass" | "fail" | "warning") => {
    switch (status) {
      case "pass":
        return (
          <svg className="h-5 w-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        )
      case "fail":
        return (
          <svg className="h-5 w-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        )
      case "warning":
        return (
          <svg className="h-5 w-5 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
            />
          </svg>
        )
    }
  }

  const exportAsJSON = () => {
    const dataStr = JSON.stringify(results, null, 2)
    const dataBlob = new Blob([dataStr], { type: "application/json" })
    const url = URL.createObjectURL(dataBlob)
    const link = document.createElement("a")
    link.href = url
    link.download = `security-audit-${new Date().toISOString().split("T")[0]}.json`
    link.click()
    URL.revokeObjectURL(url)
  }

  const exportAsPDF = async () => {
    try {
      const response = await fetch("/api/export-pdf", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(results),
      })

      if (!response.ok) throw new Error("PDF generation failed")

      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const link = document.createElement("a")
      link.href = url
      link.download = `security-audit-${new Date().toISOString().split("T")[0]}.pdf`
      link.click()
      URL.revokeObjectURL(url)
    } catch (error) {
      console.error("[v0] PDF export error:", error)
      alert("Failed to generate PDF report. Please try again.")
    }
  }

  const getComplianceColor = (status: string) => {
    switch (status) {
      case "compliant":
        return "bg-green-500/10 text-green-500 border-green-500/20"
      case "partial":
        return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20"
      case "non-compliant":
        return "bg-red-500/10 text-red-500 border-red-500/20"
      default:
        return "bg-muted text-muted-foreground"
    }
  }

  const getReputationColor = (reputation: string) => {
    switch (reputation) {
      case "safe":
        return "text-green-500"
      case "suspicious":
        return "text-yellow-500"
      case "malicious":
        return "text-red-500"
      default:
        return "text-muted-foreground"
    }
  }

  return (
    <div className="space-y-6">
      {/* Overall Score */}
      <Card className="p-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-muted-foreground">Overall Security Score</h3>
            <p className={`text-5xl font-bold mt-2 ${getScoreColor(results.score)}`}>{results.score}</p>
          </div>
          <div className="text-right space-y-2">
            <div className="flex items-center gap-2 justify-end">
              <span className="text-sm text-muted-foreground">Target URL:</span>
              <code className="text-sm font-mono bg-muted px-2 py-1 rounded">{results.url}</code>
            </div>
            <div className="flex items-center gap-2 justify-end">
              <span className="text-sm text-muted-foreground">Scanned:</span>
              <span className="text-sm">{new Date(results.timestamp).toLocaleString()}</span>
            </div>
            <div className="flex items-center gap-2 justify-end mt-4">
              <Button onClick={exportAsJSON} variant="outline" size="sm">
                <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                  />
                </svg>
                Export JSON
              </Button>
              <Button onClick={exportAsPDF} variant="outline" size="sm">
                <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"
                  />
                </svg>
                Export PDF
              </Button>
            </div>
          </div>
        </div>
        <div className="mt-6 grid grid-cols-3 gap-4">
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">Passed</p>
            <p className="text-2xl font-semibold text-green-500">{results.summary.passed}</p>
          </div>
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">Warnings</p>
            <p className="text-2xl font-semibold text-yellow-500">{results.summary.warnings}</p>
          </div>
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">Failed</p>
            <p className="text-2xl font-semibold text-red-500">{results.summary.failed}</p>
          </div>
        </div>
      </Card>

      {/* Domain Intelligence */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Domain Intelligence</h3>
        <div className="space-y-4">
          {/* Threat Intelligence */}
          <div className="p-4 rounded-md border border-border">
            <div className="flex items-center justify-between mb-3">
              <h4 className="font-medium">Threat Intelligence</h4>
              <Badge className={getReputationColor(results.domainIntelligence.threatIntelligence.reputation)}>
                {results.domainIntelligence.threatIntelligence.reputation.toUpperCase()}
              </Badge>
            </div>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-muted-foreground">Blacklisted:</span>
                <span className="ml-2 font-medium">
                  {results.domainIntelligence.threatIntelligence.isBlacklisted ? "Yes" : "No"}
                </span>
              </div>
              <div>
                <span className="text-muted-foreground">Threat Categories:</span>
                <span className="ml-2 font-medium">
                  {results.domainIntelligence.threatIntelligence.threatCategories.length > 0
                    ? results.domainIntelligence.threatIntelligence.threatCategories.join(", ")
                    : "None"}
                </span>
              </div>
            </div>
          </div>

          {/* Subdomains */}
          <div className="p-4 rounded-md border border-border">
            <h4 className="font-medium mb-3">Discovered Subdomains ({results.domainIntelligence.subdomains.length})</h4>
            <div className="flex flex-wrap gap-2">
              {results.domainIntelligence.subdomains.length > 0 ? (
                results.domainIntelligence.subdomains.map((subdomain, idx) => (
                  <code key={idx} className="text-xs font-mono bg-muted px-2 py-1 rounded">
                    {subdomain}
                  </code>
                ))
              ) : (
                <p className="text-sm text-muted-foreground">No subdomains discovered</p>
              )}
            </div>
          </div>

          {/* DNS Security */}
          <div className="p-4 rounded-md border border-border">
            <h4 className="font-medium mb-3">DNS Security Records</h4>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="flex items-center gap-2">
                {results.domainIntelligence.dnsRecords.hasDNSSEC ? getStatusIcon("pass") : getStatusIcon("fail")}
                <span className="text-sm font-medium">DNSSEC</span>
              </div>
              <div className="flex items-center gap-2">
                {results.domainIntelligence.dnsRecords.hasSPF ? getStatusIcon("pass") : getStatusIcon("fail")}
                <span className="text-sm font-medium">SPF</span>
              </div>
              <div className="flex items-center gap-2">
                {results.domainIntelligence.dnsRecords.hasDMARC ? getStatusIcon("pass") : getStatusIcon("fail")}
                <span className="text-sm font-medium">DMARC</span>
              </div>
              <div className="flex items-center gap-2">
                {results.domainIntelligence.dnsRecords.hasDKIM ? getStatusIcon("pass") : getStatusIcon("fail")}
                <span className="text-sm font-medium">DKIM</span>
              </div>
            </div>
          </div>
        </div>
      </Card>

      {/* SSL/TLS Certificate */}
      <Card className="p-6">
        <div className="flex items-center gap-2 mb-4">
          {getStatusIcon(results.ssl.status)}
          <h3 className="text-lg font-semibold">SSL/TLS Certificate</h3>
        </div>
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-muted-foreground">Valid:</span>
              <span className="ml-2 font-medium">{results.ssl.valid ? "Yes" : "No"}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Issuer:</span>
              <span className="ml-2 font-mono text-xs">{results.ssl.issuer}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Valid From:</span>
              <span className="ml-2 font-medium">{results.ssl.validFrom}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Valid To:</span>
              <span className="ml-2 font-medium">{results.ssl.validTo}</span>
            </div>
          </div>
          {results.ssl.recommendation && (
            <div className="mt-4 p-3 bg-muted rounded-md">
              <p className="text-sm font-medium mb-1">Recommendation:</p>
              <p className="text-sm text-muted-foreground">{results.ssl.recommendation}</p>
            </div>
          )}
        </div>
      </Card>

      {/* Security Headers */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">HTTP Security Headers</h3>
        <div className="space-y-3">
          {results.headers.map((header, index) => (
            <div
              key={index}
              className="flex items-start gap-3 p-3 rounded-md border border-border hover:bg-accent/50 transition-colors"
            >
              <div className="mt-0.5">{getStatusIcon(header.status)}</div>
              <div className="flex-1 space-y-2">
                <div className="flex items-center justify-between">
                  <code className="text-sm font-mono font-medium">{header.name}</code>
                  <Badge variant="outline" className={getSeverityColor(header.severity)}>
                    {header.severity}
                  </Badge>
                </div>
                {header.value && (
                  <p className="text-xs font-mono text-muted-foreground bg-muted px-2 py-1 rounded">{header.value}</p>
                )}
                <p className="text-sm text-muted-foreground">{header.description}</p>
                {header.recommendation && (
                  <div className="mt-2 p-2 bg-muted/50 rounded text-xs">
                    <span className="font-medium">Fix: </span>
                    {header.recommendation}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Compliance Status */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Compliance Status</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* GDPR */}
          <div className="p-4 rounded-md border border-border">
            <div className="flex items-center justify-between mb-3">
              <h4 className="font-medium">GDPR</h4>
              <Badge variant="outline" className={getComplianceColor(results.compliance.gdpr.status)}>
                {results.compliance.gdpr.status}
              </Badge>
            </div>
            <p className="text-2xl font-bold mb-2">{results.compliance.gdpr.score}%</p>
            <div className="space-y-2">
              {results.compliance.gdpr.checks.map((check, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  {check.passed ? getStatusIcon("pass") : getStatusIcon("fail")}
                  <div className="flex-1">
                    <p className="text-sm font-medium">{check.name}</p>
                    <p className="text-xs text-muted-foreground">{check.description}</p>
                    {check.recommendation && (
                      <p className="text-xs text-yellow-500 mt-1">Fix: {check.recommendation}</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* CCPA */}
          <div className="p-4 rounded-md border border-border">
            <div className="flex items-center justify-between mb-3">
              <h4 className="font-medium">CCPA</h4>
              <Badge variant="outline" className={getComplianceColor(results.compliance.ccpa.status)}>
                {results.compliance.ccpa.status}
              </Badge>
            </div>
            <p className="text-2xl font-bold mb-2">{results.compliance.ccpa.score}%</p>
            <div className="space-y-2">
              {results.compliance.ccpa.checks.map((check, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  {check.passed ? getStatusIcon("pass") : getStatusIcon("fail")}
                  <div className="flex-1">
                    <p className="text-sm font-medium">{check.name}</p>
                    <p className="text-xs text-muted-foreground">{check.description}</p>
                    {check.recommendation && (
                      <p className="text-xs text-yellow-500 mt-1">Fix: {check.recommendation}</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* SOC2 */}
          <div className="p-4 rounded-md border border-border">
            <div className="flex items-center justify-between mb-3">
              <h4 className="font-medium">SOC 2</h4>
              <Badge variant="outline" className={getComplianceColor(results.compliance.soc2.status)}>
                {results.compliance.soc2.status}
              </Badge>
            </div>
            <p className="text-2xl font-bold mb-2">{results.compliance.soc2.score}%</p>
            <div className="space-y-2">
              {results.compliance.soc2.checks.map((check, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  {check.passed ? getStatusIcon("pass") : getStatusIcon("fail")}
                  <div className="flex-1">
                    <p className="text-sm font-medium">{check.name}</p>
                    <p className="text-xs text-muted-foreground">{check.description}</p>
                    {check.recommendation && (
                      <p className="text-xs text-yellow-500 mt-1">Fix: {check.recommendation}</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* PCI DSS */}
          <div className="p-4 rounded-md border border-border">
            <div className="flex items-center justify-between mb-3">
              <h4 className="font-medium">PCI DSS</h4>
              <Badge variant="outline" className={getComplianceColor(results.compliance.pciDss.status)}>
                {results.compliance.pciDss.status}
              </Badge>
            </div>
            <p className="text-2xl font-bold mb-2">{results.compliance.pciDss.score}%</p>
            <div className="space-y-2">
              {results.compliance.pciDss.checks.map((check, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  {check.passed ? getStatusIcon("pass") : getStatusIcon("fail")}
                  <div className="flex-1">
                    <p className="text-sm font-medium">{check.name}</p>
                    <p className="text-xs text-muted-foreground">{check.description}</p>
                    {check.recommendation && (
                      <p className="text-xs text-yellow-500 mt-1">Fix: {check.recommendation}</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Card>

      {/* Vulnerabilities */}
      {results.vulnerabilities.length > 0 && (
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4">Detected Vulnerabilities</h3>
          <div className="space-y-3">
            {results.vulnerabilities.map((vuln, index) => (
              <div key={index} className="flex items-start gap-3 p-4 rounded-md border border-border bg-card">
                <div className="mt-0.5">{getStatusIcon("fail")}</div>
                <div className="flex-1 space-y-2">
                  <div className="flex items-center justify-between">
                    <h4 className="font-semibold">{vuln.name}</h4>
                    <Badge variant="outline" className={getSeverityColor(vuln.severity)}>
                      {vuln.severity}
                    </Badge>
                  </div>
                  <p className="text-sm text-muted-foreground">{vuln.description}</p>
                  <div className="mt-3 p-3 bg-muted rounded-md">
                    <p className="text-sm font-medium mb-1">Recommendation:</p>
                    <p className="text-sm text-muted-foreground">{vuln.recommendation}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
