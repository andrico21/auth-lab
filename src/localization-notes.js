import { LEARNING_NOTES } from './protocol-data.js';

// Stable external ownership; verification binds each source index to exact English bytes.
// Locale selection never examines a title or changes a canonical note.
export const FOOTER_NOTE_BINDINGS = Object.freeze([
  Object.freeze({id:"one-authenticator-per-attempt",sourceIndex:1,sourceSha256:"a3130b3be6249261d5d203b3a9eaf10efdf8422420190d99740b07555228db9c",note:LEARNING_NOTES[1]}),
  Object.freeze({id:"sessions-can-shorten-sign-in",sourceIndex:6,sourceSha256:"b3bf45f2a2a6a93b6fcd6c89e6c73b8f7e3f7e41506a46c5c756f1ce586eade1",note:LEARNING_NOTES[6]}),
  Object.freeze({id:"configured-passkey-totp-flow",sourceIndex:10,sourceSha256:"08bdf93789e3e31272b5d228ba503acc63cb95cad172ec3f5a53eb0192dc80cf",note:LEARNING_NOTES[10]}),
  Object.freeze({id:"totp-phishing-boundary",sourceIndex:12,sourceSha256:"d062aee334999005bb35876a0907ce38c96e3f7bb641b77253718d6ee4a10678",note:LEARNING_NOTES[12]}),
]);
