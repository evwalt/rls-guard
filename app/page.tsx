"use client";

import { useEffect, useState } from "react";
import { detect, summarize, type TableScan, type Finding } from "@/lib/detect";
import { SCAN_QUERY } from "@/lib/scan-query";

const STORAGE_KEY = "rls-guard-scan-v1";

export default function Page() {
  const [pasteInput, setPasteInput] = useState("");
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);
  const [unlocked, setUnlocked] = useState(false);
  const [checkoutLoading, setCheckoutLoading] = useState(false);
  const [copiedQuery, setCopiedQuery] = useState(false);

  // Round-trip through Stripe Checkout leaves this page and comes back.
  // The scan itself never touches our server — we stash it in
  // sessionStorage (client-only) purely so the user doesn't have to
  // re-paste after paying.
  useEffect(() => {
    const saved = sessionStorage.getItem(STORAGE_KEY);
    if (saved) {
      try {
        const scan: TableScan[] = JSON.parse(saved);
        setFindings(detect(scan));
      } catch {
        // ignore corrupt cache
      }
    }

    const params = new URLSearchParams(window.location.search);
    const sessionId = params.get("session_id");
    if (sessionId) {
      fetch(`/api/verify-session?session_id=${encodeURIComponent(sessionId)}`)
        .then((r) => r.json())
        .then((data) => {
          if (data.paid) setUnlocked(true);
        })
        .catch(() => {});
    }
  }, []);

  function handleAnalyze() {
    setParseError(null);
    try {
      const scan: TableScan[] = JSON.parse(pasteInput);
      if (!Array.isArray(scan)) throw new Error("Expected a JSON array");
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(scan));
      setFindings(detect(scan));
    } catch (e) {
      setParseError(
        "That didn't parse as the expected JSON. Make sure you copied the full value of the scan_result cell from the SQL Editor."
      );
    }
  }

  async function handleUnlock() {
    setCheckoutLoading(true);
    try {
      const res = await fetch("/api/create-checkout-session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ origin: window.location.origin }),
      });
      const data = await res.json();
      if (data.url) window.location.href = data.url;
    } finally {
      setCheckoutLoading(false);
    }
  }

  function copyQuery() {
    navigator.clipboard.writeText(SCAN_QUERY);
    setCopiedQuery(true);
    setTimeout(() => setCopiedQuery(false), 2000);
  }

  const summary = findings ? summarize(findings) : null;

  return (
    <main style={{ maxWidth: 720, margin: "0 auto", padding: "48px 20px 96px" }}>
      <h1 style={{ fontSize: 32, lineHeight: 1.25 }}>
        Does your Supabase app let other users read each other&apos;s data?
      </h1>
      <p style={{ color: "#9aa7b0", fontSize: 17 }}>
        91.5% of AI-generated ("vibe-coded") apps shipped with at least one
        vulnerability in Q1 2026 — missing Row-Level-Security is the single
        most common one. Check yours in about a minute. We never see your
        connection string, and the scan never leaves your browser.
      </p>

      <section style={{ marginTop: 40 }}>
        <h2 style={{ fontSize: 20 }}>Step 1 — run this in your Supabase SQL Editor</h2>
        <p style={{ color: "#9aa7b0" }}>
          It&apos;s a read-only <code>select</code> against Postgres&apos;s own system
          catalogs — nothing here can modify your database. Read it before you
          run it.
        </p>
        <pre
          style={{
            background: "#161b22",
            padding: 16,
            borderRadius: 8,
            overflowX: "auto",
            fontSize: 13,
          }}
        >
          {SCAN_QUERY}
        </pre>
        <button onClick={copyQuery} style={buttonStyle}>
          {copiedQuery ? "Copied" : "Copy query"}
        </button>
      </section>

      <section style={{ marginTop: 40 }}>
        <h2 style={{ fontSize: 20 }}>Step 2 — paste the result back here</h2>
        <p style={{ color: "#9aa7b0" }}>
          Click the single <code>scan_result</code> cell in the SQL Editor&apos;s
          output and paste its full value below.
        </p>
        <textarea
          value={pasteInput}
          onChange={(e) => setPasteInput(e.target.value)}
          placeholder='[{"schemaname":"public","tablename":"orders", ...}]'
          rows={8}
          style={{
            width: "100%",
            background: "#161b22",
            color: "#e6edf3",
            border: "1px solid #30363d",
            borderRadius: 8,
            padding: 12,
            fontFamily: "monospace",
            fontSize: 13,
          }}
        />
        <div>
          <button onClick={handleAnalyze} style={{ ...buttonStyle, marginTop: 12 }}>
            Analyze
          </button>
        </div>
        {parseError && <p style={{ color: "#f85149" }}>{parseError}</p>}
      </section>

      {summary && (
        <section id="results" style={{ marginTop: 40 }}>
          <h2 style={{ fontSize: 20 }}>Results</h2>
          <p>
            <strong>{summary.total}</strong> issue{summary.total === 1 ? "" : "s"} found —{" "}
            {summary.high} that could expose or corrupt other users&apos; data,{" "}
            {summary.info} configuration warning{summary.info === 1 ? "" : "s"}.
          </p>

          {summary.total === 0 && (
            <p style={{ color: "#3fb950" }}>
              No RLS issues found in this scan class. (This checks one
              vulnerability class only — it is not a full security audit.)
            </p>
          )}

          {summary.total > 0 && !unlocked && (
            <div
              style={{
                border: "1px solid #30363d",
                borderRadius: 8,
                padding: 20,
                marginTop: 16,
              }}
            >
              <p>
                Unlock which tables are affected and the exact SQL to fix
                each one.
              </p>
              <button
                onClick={handleUnlock}
                disabled={checkoutLoading}
                style={primaryButtonStyle}
              >
                {checkoutLoading ? "Redirecting…" : "Buy RLS Guard — $12 one-time"}
              </button>
            </div>
          )}

          {summary.total > 0 && unlocked && (
            <div style={{ marginTop: 16 }}>
              {findings!.map((f, i) => (
                <div
                  key={i}
                  style={{
                    border: "1px solid #30363d",
                    borderRadius: 8,
                    padding: 16,
                    marginBottom: 12,
                  }}
                >
                  <p style={{ fontWeight: 600 }}>
                    {f.severity === "high" ? "⚠️ " : "ℹ️ "}
                    {f.table} — {f.title}
                  </p>
                  <p style={{ color: "#9aa7b0" }}>{f.detail}</p>
                  <pre
                    style={{
                      background: "#161b22",
                      padding: 12,
                      borderRadius: 8,
                      overflowX: "auto",
                      fontSize: 13,
                    }}
                  >
                    {f.fixSql}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      <footer style={{ marginTop: 64, color: "#6e7681", fontSize: 13 }}>
        Checks one vulnerability class (Postgres/Supabase Row-Level-Security
        misconfiguration) against metadata you paste in yourself. Not a full
        security audit. Nothing you paste is sent to our server — analysis
        runs in your browser.
      </footer>
    </main>
  );
}

const buttonStyle: React.CSSProperties = {
  background: "#21262d",
  color: "#e6edf3",
  border: "1px solid #30363d",
  borderRadius: 6,
  padding: "8px 16px",
  cursor: "pointer",
  fontSize: 14,
};

const primaryButtonStyle: React.CSSProperties = {
  ...buttonStyle,
  background: "#238636",
  border: "1px solid #2ea043",
};
