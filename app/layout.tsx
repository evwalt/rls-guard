import type { Metadata, Viewport } from "next";

const siteUrl = "https://rls-guard.evanwalter.dev";
const title = "RLS Guard: check your Supabase app for the #1 vibe-coding data leak";
const description =
  "Paste one read-only query's output from your own Supabase SQL Editor. Find out in seconds whether other users can read or write your data.";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: {
    default: title,
    template: "%s · RLS Guard",
  },
  description,
  alternates: {
    canonical: "/",
  },
  robots: {
    index: true,
    follow: true,
  },
  openGraph: {
    title,
    description,
    url: siteUrl,
    siteName: "RLS Guard",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title,
    description,
  },
  icons: {
    icon: [
      { url: "/favicon.svg", type: "image/svg+xml" },
      { url: "/favicon-32x32.png", sizes: "32x32", type: "image/png" },
      { url: "/favicon-16x16.png", sizes: "16x16", type: "image/png" },
    ],
    apple: "/apple-icon.png",
  },
};

export const viewport: Viewport = {
  themeColor: "#0b0f14",
};

const jsonLd = {
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  name: "RLS Guard",
  description:
    "Read-only scanner that checks a Supabase/Postgres project for missing or misconfigured Row-Level Security and generates the exact fix SQL.",
  url: siteUrl,
  applicationCategory: "SecurityApplication",
  operatingSystem: "Web",
  creator: {
    "@type": "Person",
    name: "Evan Walter",
  },
  offers: {
    "@type": "Offer",
    price: "29",
    priceCurrency: "USD",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, fontFamily: "system-ui, sans-serif", background: "#0b0f14", color: "#e6edf3" }}>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        {children}
      </body>
    </html>
  );
}
