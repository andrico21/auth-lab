import {createHash} from 'node:crypto';

// Source mode needs same-origin modules, stylesheet and supplied favicon files.
// The standalone build embeds icons and hashes its exact script and stylesheet.
const policy = (scriptSource, styleSource, imageSource) => [
  "default-src 'none'",
  `script-src ${scriptSource}`,
  "script-src-attr 'none'",
  `style-src ${styleSource}`,
  "style-src-attr 'none'",
  "connect-src 'none'",
  `img-src ${imageSource}`,
  "font-src 'none'",
  "media-src 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "worker-src 'none'",
  "manifest-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

export const SOURCE_CSP = policy("'self'", "'self'", "'self'");

// HTML parsing normalizes CRLF and CR. Emit LF before hashing so builds made
// from Windows-edited sources also match the text that browsers actually parse.
export const normalizeHtmlLines = text => text.replace(/\r\n?/g, '\n');
const contentHash = text => "'sha256-" + createHash('sha256').update(normalizeHtmlLines(text), 'utf8').digest('base64') + "'";
export const standaloneCsp = (script, style) => policy(contentHash(script), contentHash(style), 'data:');
export const cspMeta = value => `<meta http-equiv="Content-Security-Policy" content="${value}">`;
