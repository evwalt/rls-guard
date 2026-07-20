import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "RLS Guard: check your Supabase app for the #1 vibe-coding data leak",
  description:
    "Paste one read-only query's output from your own Supabase SQL Editor. Find out in seconds whether other users can read or write your data.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, fontFamily: "system-ui, sans-serif", background: "#0b0f14", color: "#e6edf3" }}>
        {children}
      </body>
    </html>
  );
}
