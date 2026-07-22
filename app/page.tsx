"use client";

import { useEffect, useState } from "react";
import {
  detect,
  summarize,
  categorizeFindings,
  scanMeta,
  type TableScan,
  type Finding,
} from "@/lib/detect";
import { normalizeScanInput } from "@/lib/normalize-scan-input";
import { SCAN_QUERY } from "@/lib/scan-query";

const STORAGE_KEY = "rls-guard-scan-v1";

type Meta = {
  tablesScanned: number;
  policiesAnalyzed: number;
  durationMs: number;
};

function formatDuration(ms: number): string {
  if (ms < 1) return "<1 ms";
  return `${Math.round(ms)} ms`;
}

export default function Page() {
  const [pasteInput, setPasteInput] = useState("");
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);
  const [unlocked, setUnlocked] = useState(false);
  const [checkoutLoading, setCheckoutLoading] = useState(false);
  const [copiedQuery, setCopiedQuery] = useState(false);

  // Timed so the results page can show real scan duration as evidence that
  // analysis actually ran against the pasted metadata, not a canned number.
  function runScan(scan: TableScan[]) {
    const start = performance.now();
    const detected = detect(scan);
    const durationMs = performance.now() - start;
    setFindings(detected);
    setMeta({ ...scanMeta(scan), durationMs });
  }

  // Round-trip through Stripe Checkout leaves this page and comes back.
  // The scan itself never touches our server — we stash it in
  // sessionStorage (client-only) purely so the user doesn't have to
  // re-paste after paying.
  useEffect(() => {
    const saved = sessionStorage.getItem(STORAGE_KEY);
    if (saved) {
      try {
        const scan: TableScan[] = JSON.parse(saved);
        runScan(scan);
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
      const parsed = JSON.parse(pasteInput);
      const scan = normalizeScanInput(parsed);
      if (!Array.isArray(scan)) throw new Error("Unrecognized scan shape");
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(scan));
      runScan(scan as TableScan[]);
    } catch (e) {
      setParseError(
        "We couldn't recognize this Supabase result. Copy the full result from the SQL Editor and paste it here without editing it."
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
  const categories = findings ? categorizeFindings(findings) : [];

  return (
    <main style={{ maxWidth: 720, margin: "0 auto", padding: "48px 20px 96px" }}>
      <h1 style={{ fontSize: 32, lineHeight: 1.25 }}>
        RLS Guard: check whether your Supabase app leaks other users&apos; data
      </h1>
      <p style={{ color: "#9aa7b0", fontSize: 17 }}>
        A read-only Supabase RLS scan that shows whether your app may be
        exposing other users&apos; data, especially common in AI-assisted
        ("vibe-coded") apps. Run one short, auditable{" "}
        <code>select</code> query in your own Supabase SQL Editor and paste
        the result here. The scan is free; detailed findings and exact
        remediation SQL are available for a one-time $29 payment. We never
        see a connection string, and nothing you paste leaves your browser.
      </p>

      <section style={{ marginTop: 40 }}>
        <h2 style={{ fontSize: 20 }}>Step 1: run this in your Supabase SQL Editor</h2>
        <p style={{ color: "#9aa7b0" }}>
          It&apos;s a read-only <code>select</code> against Postgres&apos;s own system
          catalogs; nothing here can modify your database. Read it before you
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
        <h2 style={{ fontSize: 20 }}>Step 2: paste the result back here</h2>
        <p style={{ color: "#9aa7b0" }}>
          Copy the result from Supabase and paste it here as-is.
        </p>
        <textarea
          value={pasteInput}
          onChange={(e) => setPasteInput(e.target.value)}
          placeholder='[{"schemaname":"public","tablename":"orders", ...}]'
          rows={8}
          style={{
            width: "100%",
            boxSizing: "border-box",
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

          <p style={{ fontWeight: 600 }}>
            {summary.total} finding{summary.total === 1 ? "" : "s"} detected
          </p>

          {summary.total > 0 && (
            <ul style={{ listStyle: "none", padding: 0, margin: "8px 0 0" }}>
              {categories.map((c) => (
                <li key={c.text} style={{ color: "#9aa7b0" }}>
                  ✓ {c.text}
                </li>
              ))}
            </ul>
          )}

          {meta && (
            <p style={{ color: "#6e7681", fontSize: 14, marginTop: 12 }}>
              Scanned {meta.tablesScanned} table{meta.tablesScanned === 1 ? "" : "s"} •{" "}
              {meta.policiesAnalyzed} polic{meta.policiesAnalyzed === 1 ? "y" : "ies"} •{" "}
              {summary.total} finding{summary.total === 1 ? "" : "s"} •{" "}
              {formatDuration(meta.durationMs)}
            </p>
          )}

          <p style={{ color: "#6e7681", fontSize: 13, marginTop: 8 }}>
            Analysis is performed entirely in your browser. Your metadata is
            never uploaded.
          </p>

          {summary.total === 0 && (
            <p style={{ color: "#3fb950", marginTop: 16 }}>
              No RLS issues found in this scan class. (This checks one
              vulnerability class only; it is not a full security audit.)
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
              <p style={{ fontWeight: 600 }}>Unlock the full report:</p>
              <ul style={{ margin: "8px 0", paddingLeft: 20, color: "#9aa7b0" }}>
                <li>Affected table names</li>
                <li>Policy names</li>
                <li>Severity explanations</li>
                <li>Exact remediation SQL</li>
                <li>Copyable SQL fixes</li>
              </ul>
              <button
                onClick={handleUnlock}
                disabled={checkoutLoading}
                style={primaryButtonStyle}
              >
                {checkoutLoading ? "Redirecting…" : "Unlock the fix: $29 one-time"}
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
                    {f.table}: {f.title}
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
        security audit. Nothing you paste is sent to our server: analysis
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
