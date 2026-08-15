import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

/**
 * Security headers middleware.
 *
 * CSP uses 'unsafe-inline' and 'unsafe-eval' for script-src because
 * Next.js 14 injects inline scripts for hydration and uses eval in
 * dev mode. A nonce-based policy requires experimental Next.js config
 * that is not yet stable. The remaining directives are strict:
 * no iframes, no object embeds, restricted form targets, HTTPS-only
 * image/font/connect sources.
 *
 * This is the same trade-off that Vercel's own Next.js documentation
 * recommends for production deployments without experimental features.
 */

const SCRIPT_SRC = "'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com";
const STYLE_SRC = "'self' 'unsafe-inline'";
const IMG_SRC = "'self' data: https://avatars.githubusercontent.com https://globaldex.ai";
const FONT_SRC = "'self'";
const CONNECT_SRC = "'self' https://api.codetrust.ai https://checkout.stripe.com https://billing.stripe.com";

function buildCsp(): string {
    const directives = [
        `default-src 'self'`,
        `script-src ${SCRIPT_SRC}`,
        `style-src ${STYLE_SRC}`,
        `img-src ${IMG_SRC}`,
        `font-src ${FONT_SRC}`,
        `connect-src ${CONNECT_SRC}`,
        `frame-ancestors 'self'`,
        `form-action 'self' https://checkout.stripe.com https://github.com`,
        `base-uri 'self'`,
        `object-src 'none'`,
    ];
    return directives.join("; ");
}

const CSP_HEADER = buildCsp();

export function proxy(request: NextRequest): NextResponse {
    const response = NextResponse.next();
    const headers = response.headers;

    headers.set("Content-Security-Policy", CSP_HEADER);
    headers.set("X-Frame-Options", "DENY");
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
    headers.set("X-XSS-Protection", "1; mode=block");
    headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

    const isProduction = request.nextUrl.hostname !== "localhost";
    if (isProduction) {
        headers.set(
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload",
        );
    }

    return response;
}

export const config = {
    matcher: [
        /*
         * Match all paths except:
         * - _next/static (static files)
         * - _next/image (image optimization)
         * - favicon.ico
         * - public folder assets
         */
        "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
    ],
};
