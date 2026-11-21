import type { Metadata } from "next";
import { ArrowLeft } from "lucide-react";
import { buttonVariants } from "@/components/ui/button";
import { Brand } from "@/components/site-header";

export const metadata: Metadata = {
  title: "Page not found | M5 Guardian",
  robots: { index: false },
};

export default function NotFound() {
  return (
    <>
      <header className="site-header">
        <div className="container header-inner">
          <Brand />
        </div>
      </header>
      <main id="main" className="not-found container">
        <span className="eyebrow">404 / NOT FOUND</span>
        <h1>Nothing heard at this address.</h1>
        <p>The page you asked for does not exist on this website.</p>
        <a href="/" className={buttonVariants({ size: "hero" })}>
          <ArrowLeft data-icon="inline-start" aria-hidden="true" /> Back to the
          home page
        </a>
      </main>
    </>
  );
}
