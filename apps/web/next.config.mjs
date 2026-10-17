/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  async redirects() {
    // Preserve known entry points from the separately hosted prototype on cut-over.
    return [
      { source: "/demo", destination: "/scan", permanent: true },
      { source: "/demo/context", destination: "/method", permanent: true },
      { source: "/features", destination: "/method", permanent: true },
      { source: "/how-it-works", destination: "/method", permanent: true },
      { source: "/security", destination: "/method", permanent: true },
      { source: "/tactics", destination: "/method", permanent: true },
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
    ];
  },
};

export default nextConfig;
