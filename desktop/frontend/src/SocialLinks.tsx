import { openExternalUrl } from "./wails";

const links = [
  { name: "YouTube", url: "https://www.youtube.com/@WhiteDNS?sub_confirmation=1", className: "social-youtube" },
  { name: "Telegram", url: "https://t.me/whitedns", className: "social-telegram" },
];

export function SocialLinks() {
  return <nav aria-label="WhiteDNS community" className="social-links">
    {links.map(link => <a key={link.name} href={link.url} target="_blank" rel="noopener noreferrer"
      aria-label={`WhiteDNS on ${link.name}`} className={link.className}
      onClick={event => { event.preventDefault(); openExternalUrl(link.url); }}>
      {link.name === "YouTube" ? <svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M23 7s-.2-1.6-.9-2.3c-.8-.9-1.7-.9-2.1-1C17 3.5 12 3.5 12 3.5s-5 0-8 .2c-.4.1-1.3.1-2.1 1C1.2 5.4 1 7 1 7S.8 8.9.8 10.8v1.8C.8 14.5 1 16.4 1 16.4s.2 1.6.9 2.3c.8.9 1.9.9 2.4 1 1.7.2 7.7.2 7.7.2s5 0 8-.3c.4 0 1.3-.1 2.1-.9.7-.7.9-2.3.9-2.3s.2-1.9.2-3.8v-1.8C23.2 8.9 23 7 23 7ZM9.7 15.1V8.5l6.3 3.3-6.3 3.3Z" /></svg>
        : <svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="m21.4 3.1-3.2 17.1c-.2 1.2-.9 1.5-1.9.9l-4.9-3.6-2.4 2.3c-.3.3-.5.5-1 .5l.4-5 9-8.1c.4-.4-.1-.6-.6-.3L5.7 13.8 1 12.3c-1-.3-1-1 .2-1.5L19.6 3c.8-.3 1.6.2 1.8.1Z" /></svg>}
      <span>{link.name}</span>
    </a>)}
  </nav>;
}
