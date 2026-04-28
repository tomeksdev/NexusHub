import { useEffect, useId, useRef, type ReactNode } from "react";

import { useEscapeKey } from "../lib/hooks";

// Modal is the app's single dialog wrapper. It owns the a11y
// scaffolding (role=dialog, aria-modal, aria-labelledby), Escape-to-
// close, initial focus, and the backdrop click handler. Page-level
// modals render their form inside the children prop and stay focused
// on content, not on plumbing.
//
// Focus management: on mount we move focus into the dialog if it
// isn't already there. We deliberately do NOT trap Tab — a proper
// trap needs a focus-guard + tab-key handler, which is bigger than
// this surface warrants. Most keyboard users stay within the form
// anyway; the Escape binding covers the main escape hatch.
interface ModalProps {
  title: string;
  onClose: () => void;
  children: ReactNode;
  // Optional aria-describedby content; when present it renders as a
  // subtitle and is linked via aria-describedby for screen readers.
  description?: string;
  // Controls max width; defaults to 2xl. Options keep Tailwind-y so
  // future modals can go wider without touching the wrapper.
  maxWidthClass?: string;
}

export function Modal({
  title,
  onClose,
  children,
  description,
  maxWidthClass = "max-w-2xl",
}: ModalProps) {
  const titleId = useId();
  const descId = useId();
  const contentRef = useRef<HTMLDivElement>(null);

  useEscapeKey(onClose);

  useEffect(() => {
    // Move initial focus into the dialog so screen readers announce
    // the title on open and keyboard users don't start in the
    // backdrop. We target the dialog container itself; the form's
    // autoFocus on the first input (when present) will take over.
    contentRef.current?.focus();
  }, []);

  return (
    <div
      className="fixed inset-0 bg-slate-950/70 flex items-center justify-center p-4 z-50"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={contentRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descId : undefined}
        tabIndex={-1}
        className={`bg-slate-900 border border-slate-800 rounded-lg w-full ${maxWidthClass} max-h-[90vh] overflow-y-auto focus-visible:outline-2 focus-visible:outline-indigo-500 focus-visible:outline-offset-2`}
      >
        <div className="p-6 space-y-4">
          <header className="flex items-baseline justify-between">
            <div>
              <h2 id={titleId} className="text-lg font-semibold">
                {title}
              </h2>
              {description && (
                <p id={descId} className="text-xs text-slate-500 mt-0.5">
                  {description}
                </p>
              )}
            </div>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close dialog"
              className="text-slate-500 hover:text-slate-200 text-sm focus-visible:outline-2 focus-visible:outline-indigo-500 rounded"
            >
              ✕
            </button>
          </header>
          {children}
        </div>
      </div>
    </div>
  );
}
