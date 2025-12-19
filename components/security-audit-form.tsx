"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card } from "@/components/ui/card"
import { SecurityResults } from "@/components/security-results"
import type { SecurityAuditResult } from "@/types/security"

export function SecurityAuditForm() {
  const [url, setUrl] = useState("")
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState<SecurityAuditResult | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!url) return

    setLoading(true)

    try {
      const response = await fetch("/api/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      })

      const data = await response.json()
      setResults(data)
    } catch (error) {
      console.error("Audit failed:", error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-8">
      <div className="space-y-4">
        <div className="space-y-2">
          <h2 className="text-3xl font-semibold tracking-tight">Analyze Website Security</h2>
          <p className="text-muted-foreground">
            Enter a URL to scan for common security vulnerabilities, SSL/TLS configuration, and HTTP security headers.
          </p>
        </div>

        <Card className="p-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex gap-3">
              <Input
                type="url"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="flex-1 font-mono"
                required
              />
              <Button type="submit" disabled={loading} className="px-8">
                {loading ? (
                  <>
                    <svg
                      className="mr-2 h-4 w-4 animate-spin"
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                    >
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                      />
                    </svg>
                    Analyzing...
                  </>
                ) : (
                  "Scan Website"
                )}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              This tool performs a comprehensive security analysis including SSL certificates, security headers, and
              common vulnerabilities.
            </p>
          </form>
        </Card>
      </div>

      {results && <SecurityResults results={results} />}
    </div>
  )
}
