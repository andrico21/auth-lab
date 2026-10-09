import {createHash} from 'node:crypto';

// Source mode needs same-origin module imports and its external stylesheet.
// The standalone build replaces both sources with exact content hashes.
const policy = (scriptSource, styleSource) => [
  "default-src 'none'",
  `script-src ${scriptSource}`,
  "script-src-attr 'none'",
  `style-src ${styleSource}`,
  "style-src-attr 'none'",
  "connect-src 'none'",
  "img-src 'none'",
  "font-src 'none'",
  "media-src 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "worker-src 'none'",
  "manifest-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

export const SOURCE_CSP = policy("'self'", "'self'");

// HTML parsing normalizes CRLF and CR. Emit LF before hashing so builds made
// from Windows-edited sources also match the text that browsers actually parse.
export const normalizeHtmlLines = text => text.replace(/\r\n?/g, '\n');
const contentHash = text => "'sha256-" + createHash('sha256').update(normalizeHtmlLines(text), 'utf8').digest('base64') + "'";
export const standaloneCsp = (script, style) => policy(contentHash(script), contentHash(style));
export const cspMeta = value => `<meta http-equiv="Content-Security-Policy" content="${value}">`;
