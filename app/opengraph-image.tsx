import { ImageResponse } from "next/og";

export const alt =
  "RLS Guard: check your Supabase app for missing Row-Level Security";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          alignItems: "center",
          background: "#0b0f14",
          padding: 96,
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: 14, marginRight: 72 }}>
          <div style={{ width: 110, height: 32, borderRadius: 16, background: "#9aa7b0" }} />
          <div style={{ width: 110, height: 32, borderRadius: 16, background: "#3fb950" }} />
          <div style={{ width: 110, height: 32, borderRadius: 16, background: "#9aa7b0" }} />
        </div>
        <div style={{ display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", fontSize: 76, fontWeight: 700, color: "#e6edf3" }}>
            RLS Guard
          </div>
          <div style={{ display: "flex", fontSize: 34, color: "#9aa7b0", marginTop: 20, maxWidth: 820 }}>
            Catch missing Row-Level Security in your Supabase app
          </div>
        </div>
      </div>
    ),
    { ...size }
  );
}
