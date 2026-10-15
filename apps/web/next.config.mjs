/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  async redirects() {
    // Console URLs from before the investigation workspace moved under /app.
    return [
      { source: "/analyze", destination: "/app/analyses/new", permanent: false },
      { source: "/incidents", destination: "/app/analyses", permanent: false },
      { source: "/incidents/:id", destination: "/app/analyses/:id", permanent: false },
      { source: "/events", destination: "/app/activity", permanent: false },
      { source: "/settings", destination: "/app/settings", permanent: false },
      { source: "/protection", destination: "/app", permanent: false },
      { source: "/devices", destination: "/app", permanent: false },
      { source: "/policies", destination: "/app", permanent: false },
    ];
  },
  async headers() {
    // The Content-Security-Policy header is set per request (with a nonce) in src/middleware.ts.
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
        ],
      },
      {
        // Belt and braces: private surfaces are never indexed, whatever the page metadata says.
        source: "/(app|api|connect|demo/cases)/:path*",
        headers: [{ key: "X-Robots-Tag", value: "noindex, nofollow" }],
      },
    ];
  },
};

export default nextConfig;
