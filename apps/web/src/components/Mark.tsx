/** Engraved Teger roundel: beaded bronze rim, incised T, two route arcs. Original artwork. */
export function Mark({ size = 36, title }: { size?: number; title?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" role={title ? "img" : undefined}
      aria-hidden={title ? undefined : true} aria-label={title}>
      <circle cx="32" cy="32" r="31" fill="#987044" />
      <circle cx="32" cy="32" r="28.6" fill="none" stroke="#3b2a16" strokeWidth="2" strokeDasharray="0.01 3.6"
        strokeLinecap="round" />
      <circle cx="32" cy="32" r="25.5" fill="#171A18" />
      <path d="M19.5 18.5h25v4.2h-2.3l-1.4-1.9h-5.3V44l2.6 2.2v1.3h-12.2v-1.3l2.6-2.2V20.8h-5.3l-1.4 1.9h-2.3z"
        fill="#C4AA78" />
      <path d="M14.5 41.5c4-6 7.5-8.6 11-9.2M38.6 32.2c3.6.6 7 3.3 10.9 9.3" fill="none" stroke="#C4AA78"
        strokeWidth="1.2" strokeDasharray="1.2 2.4" strokeLinecap="round" />
      <circle cx="14.5" cy="41.5" r="1.6" fill="#C4AA78" />
      <circle cx="49.5" cy="41.5" r="1.6" fill="#C4AA78" />
    </svg>
  );
}

export function Wordmark({ href = "/" }: { href?: string }) {
  return (
    <a className="wordmark" href={href} aria-label="Teger AI home">
      <Mark size={38} />
      <span className="wordmark-name">TEGER <span>AI</span></span>
    </a>
  );
}
