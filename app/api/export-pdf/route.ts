import { NextResponse } from "next/server"
import type { SecurityAuditResult } from "@/types/security"

export async function POST(request: Request) {
  try {
    const results: SecurityAuditResult = await request.json()

    // Generate PDF content
    const pdfContent = generatePDFReport(results)

    // In a real implementation, use a library like jsPDF or Puppeteer to generate actual PDFs
    // For this demo, we'll create a simple HTML-to-PDF-ready format
    const htmlContent = generateHTMLReport(results)

    // Return as downloadable file
    return new NextResponse(htmlContent, {
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="security-audit-${new Date().toISOString().split("T")[0]}.pdf"`,
      },
    })
  } catch (error) {
    console.error("[v0] PDF generation error:", error)
    return NextResponse.json({ error: "Failed to generate PDF" }, { status: 500 })
  }
}

function generatePDFReport(results: SecurityAuditResult): string {
  // This would use a proper PDF library in production
  return `Security Audit Report - ${results.url}`
}

function generateHTMLReport(results: SecurityAuditResult): string {
  // Generate an HTML report that can be printed as PDF
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Security Audit Report</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; }
    h1 { color: #1a1a1a; border-bottom: 3px solid #2563eb; padding-bottom: 10px; }
    h2 { color: #333; margin-top: 30px; border-bottom: 2px solid #e5e5e5; padding-bottom: 8px; }
    .score { font-size: 48px; font-weight: bold; color: ${results.score >= 80 ? "#22c55e" : results.score >= 60 ? "#eab308" : "#ef4444"}; }
    .summary { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }
    .summary-item { background: #f9fafb; padding: 15px; border-radius: 8px; }
    .check-item { background: #f9fafb; padding: 12px; margin: 10px 0; border-radius: 6px; border-left: 4px solid #e5e5e5; }
    .pass { border-left-color: #22c55e; }
    .fail { border-left-color: #ef4444; }
    .warning { border-left-color: #eab308; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e5e5e5; }
    th { background: #f9fafb; font-weight: 600; }
    code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
  </style>
</head>
<body>
  <h1>Security Audit Report</h1>
  
  <div style="margin: 20px 0;">
    <p><strong>Target URL:</strong> <code>${results.url}</code></p>
    <p><strong>Scan Date:</strong> ${new Date(results.timestamp).toLocaleString()}</p>
  </div>

  <div style="text-align: center; margin: 30px 0;">
    <div class="score">${results.score}</div>
    <p style="color: #666; font-size: 18px;">Overall Security Score</p>
  </div>

  <div class="summary">
    <div class="summary-item">
      <div style="font-size: 32px; font-weight: bold; color: #22c55e;">${results.summary.passed}</div>
      <div style="color: #666;">Passed</div>
    </div>
    <div class="summary-item">
      <div style="font-size: 32px; font-weight: bold; color: #eab308;">${results.summary.warnings}</div>
      <div style="color: #666;">Warnings</div>
    </div>
    <div class="summary-item">
      <div style="font-size: 32px; font-weight: bold; color: #ef4444;">${results.summary.failed}</div>
      <div style="color: #666;">Failed</div>
    </div>
  </div>

  <h2>SSL/TLS Certificate</h2>
  <div class="check-item ${results.ssl.status}">
    <p><strong>Status:</strong> ${results.ssl.valid ? "Valid" : "Invalid"}</p>
    <p><strong>Issuer:</strong> ${results.ssl.issuer}</p>
    <p><strong>Valid From:</strong> ${results.ssl.validFrom}</p>
    <p><strong>Valid To:</strong> ${results.ssl.validTo}</p>
    ${results.ssl.recommendation ? `<p style="color: #ef4444;"><strong>Recommendation:</strong> ${results.ssl.recommendation}</p>` : ""}
  </div>

  <h2>Security Headers</h2>
  ${results.headers
    .map(
      (header) => `
    <div class="check-item ${header.status}">
      <p><strong>${header.name}</strong> <span style="float: right; color: #666;">${header.severity} Severity</span></p>
      <p>${header.description}</p>
      ${header.value ? `<p><code>${header.value}</code></p>` : ""}
      ${header.recommendation ? `<p style="color: #ef4444;"><strong>Fix:</strong> ${header.recommendation}</p>` : ""}
    </div>
  `,
    )
    .join("")}

  <h2>Compliance Status</h2>
  <table>
    <thead>
      <tr>
        <th>Standard</th>
        <th>Status</th>
        <th>Score</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>GDPR</td>
        <td>${results.compliance.gdpr.status}</td>
        <td>${results.compliance.gdpr.score}%</td>
      </tr>
      <tr>
        <td>CCPA</td>
        <td>${results.compliance.ccpa.status}</td>
        <td>${results.compliance.ccpa.score}%</td>
      </tr>
      <tr>
        <td>SOC 2</td>
        <td>${results.compliance.soc2.status}</td>
        <td>${results.compliance.soc2.score}%</td>
      </tr>
      <tr>
        <td>PCI DSS</td>
        <td>${results.compliance.pciDss.status}</td>
        <td>${results.compliance.pciDss.score}%</td>
      </tr>
    </tbody>
  </table>

  <h2>Domain Intelligence</h2>
  <div class="check-item">
    <p><strong>Threat Reputation:</strong> ${results.domainIntelligence.threatIntelligence.reputation}</p>
    <p><strong>Blacklisted:</strong> ${results.domainIntelligence.threatIntelligence.isBlacklisted ? "Yes" : "No"}</p>
    <p><strong>Discovered Subdomains:</strong> ${results.domainIntelligence.subdomains.length}</p>
    ${results.domainIntelligence.subdomains.length > 0 ? `<p>${results.domainIntelligence.subdomains.map((s) => `<code>${s}</code>`).join(", ")}</p>` : ""}
  </div>

  ${
    results.vulnerabilities.length > 0
      ? `
  <h2>Vulnerabilities</h2>
  ${results.vulnerabilities
    .map(
      (vuln) => `
    <div class="check-item fail">
      <p><strong>${vuln.name}</strong> <span style="float: right; color: #666;">${vuln.severity} Severity</span></p>
      <p>${vuln.description}</p>
      <p style="color: #ef4444;"><strong>Recommendation:</strong> ${vuln.recommendation}</p>
    </div>
  `,
    )
    .join("")}
  `
      : ""
  }

  <div style="margin-top: 50px; padding-top: 20px; border-top: 2px solid #e5e5e5; text-align: center; color: #666;">
    <p>Generated by Security Audit Dashboard</p>
    <p>This report is for informational purposes only and should be reviewed by security professionals.</p>
  </div>
</body>
</html>
  `
}
