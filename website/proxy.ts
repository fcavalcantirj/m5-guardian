import { NextResponse, type NextRequest } from "next/server";
import { contentSecurityPolicy, cspHeaderName, newNonce } from "@/lib/csp";

// W08 Content-Security-Policy with a fresh nonce per page request. Next reads
// the nonce from the request's content-security-policy header and puts it on
// its inline bootstrap scripts, which is why every page is rendered per request
// (app/layout.tsx awaits connection()). Static files, the firmware API and the
// generated images, robots and sitemap carry no HTML and skip the proxy.
// GUARDIAN_CSP_REPORT_ONLY=1 sends the policy as Report-Only instead (a trial).

export function proxy(request: NextRequest) {
  const nonce = newNonce();
  const policy = contentSecurityPolicy({
    nonce,
    dev: process.env.NODE_ENV === "development",
    preview: process.env.VERCEL_ENV === "preview",
  });
  const header = cspHeaderName(process.env.GUARDIAN_CSP_REPORT_ONLY);

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("content-security-policy", policy);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set(header, policy);
  return response;
}

export const config = {
  matcher: [
    {
      source:
        "/((?!api|_next/static|_next/image|_vercel|favicon\\.ico|icon\\.svg|apple-icon\\.png|opengraph-image|twitter-image|install/opengraph-image|install/twitter-image|robots\\.txt|sitemap\\.xml|images|models).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
