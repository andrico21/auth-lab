/** Decorative, self-contained illustrations for the authentication actors. */
let illustrationSequence = 0;

const numeralSegments = {
  1: ['b', 'c'], 2: ['a', 'b', 'g', 'e', 'd'], 3: ['a', 'b', 'g', 'c', 'd'],
  4: ['f', 'g', 'b', 'c'], 5: ['a', 'f', 'g', 'c', 'd'], 6: ['a', 'f', 'g', 'e', 'c', 'd'],
};
const segmentPaths = { a: 'M1 0h3', b: 'M4.5 1v3', c: 'M4.5 6v3', d: 'M1 10h3', e: 'M.5 6v3', f: 'M.5 1v3', g: 'M1 5h3' };
const totpDigits = () => '123456'.split('').map((digit, index) =>
  `<g transform="translate(${30 + index * 6.7 + (index > 2 ? 2 : 0)} 44)">${numeralSegments[digit].map(segment => `<path d="${segmentPaths[segment]}"/>`).join('')}</g>`
).join('');

const artwork = {
  user: (p) => `
    <ellipse cx="50" cy="86" rx="32" ry="7" fill="#cdaaa1" opacity=".14"/>
    <path d="M21 81c0-17 11-28 29-28s29 11 29 28v5H21z" fill="url(#${p}-primary)" filter="url(#${p}-shadow)"/>
    <path d="M36 59l14 10 14-10-7-5H43z" fill="#fff" opacity=".95"/>
    <path d="M43 49v11c0 8 14 8 14 0V49" fill="#ecab88"/>
    <path d="M32 25c0-13 8-20 19-20 14 0 20 10 20 24v12H31z" fill="#3b2b37"/>
    <ellipse cx="33" cy="39" rx="4" ry="6" fill="#f6bb98"/>
    <ellipse cx="67" cy="39" rx="4" ry="6" fill="#f6bb98"/>
    <path d="M34 26v15c0 13 7 20 16 20s16-7 16-20V26z" fill="url(#${p}-skin)"/>
    <path d="M33 30c4-1 8-4 11-11 5 7 13 10 24 10l-3-13-22-3-10 8z" fill="#3b2b37"/>
    <circle cx="43" cy="38" r="1.7" fill="#493242"/>
    <circle cx="58" cy="38" r="1.7" fill="#493242"/>
    <path d="M46 49c3 2 6 2 9-1" fill="none" stroke="#b85b55" stroke-width="2.2" stroke-linecap="round"/>
    <path d="M26 80v-8M74 80v-8" stroke="#af4267" stroke-width="2" stroke-linecap="round" opacity=".4"/>
    <circle cx="79" cy="19" r="10" fill="#fff" stroke="#f4d8df"/>
    <path d="M75 19l3 3 5-6" fill="none" stroke="#dd5c87" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
  `,
  app: (p) => `
    <ellipse cx="49" cy="84" rx="40" ry="6" fill="#4b6fbb" opacity=".13"/>
    <g filter="url(#${p}-shadow)">
      <rect x="17" y="16" width="68" height="57" rx="7" fill="#243951"/>
      <rect x="21" y="20" width="60" height="48" rx="3" fill="#eef5ff"/>
      <path d="M21 23a3 3 0 0 1 3-3h54a3 3 0 0 1 3 3v7H21z" fill="#cddaf6"/>
      <circle cx="26" cy="25" r="1.7" fill="#8296c7"/>
      <circle cx="32" cy="25" r="1.7" fill="#8296c7"/>
      <circle cx="38" cy="25" r="1.7" fill="#8296c7"/>
      <path d="M17 72h68l9 8c1 2-1 4-5 4H11c-4 0-6-2-4-4z" fill="#b8c7e3"/>
      <path d="M37 72h28l4 5H33z" fill="#8a9dbf"/>
      <path d="M8 80h85" stroke="#d9e3f4" stroke-width="2"/>
    </g>
    <rect x="26" y="36" width="19" height="23" rx="5" fill="url(#${p}-primary)"/>
    <path d="M32 43l-3 4 3 4m7-8 3 4-3 4" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M51 39h22M51 45h16M51 51h20" stroke="#a2b4d7" stroke-width="3" stroke-linecap="round"/>
    <rect x="51" y="57" width="20" height="5" rx="2.5" fill="#5b8cee"/>
    <circle cx="82" cy="16" r="10" fill="#fff" stroke="#dae5fb"/>
    <path d="M80 12h4v8h-4m-3-5v3m10-3v3" fill="none" stroke="#658bed" stroke-width="1.8" stroke-linecap="round"/>
  `,
  browser: (p) => `
    <ellipse cx="51" cy="84" rx="38" ry="6" fill="#388bb0" opacity=".12"/>
    <g filter="url(#${p}-shadow)">
      <rect x="10" y="17" width="78" height="60" rx="8" fill="#e9f5fb" stroke="#b6d9e9"/>
      <path d="M18 17h62a8 8 0 0 1 8 8v7H10v-7a8 8 0 0 1 8-8z" fill="#d2e9f4"/>
      <circle cx="18" cy="24" r="2" fill="#8fa8be"/>
      <circle cx="25" cy="24" r="2" fill="#8fa8be"/>
      <circle cx="32" cy="24" r="2" fill="#8fa8be"/>
      <rect x="41" y="21" width="38" height="7" rx="3.5" fill="#f9fcff"/>
    </g>
    <circle cx="49" cy="54" r="23" fill="url(#${p}-primary)"/>
    <ellipse cx="49" cy="54" rx="10" ry="23" fill="none" stroke="#dcf8ff" stroke-width="1.4" opacity=".8"/>
    <path d="M28 46h42M27 61h44M49 31v46" fill="none" stroke="#dcf8ff" stroke-width="1.4" opacity=".8"/>
    <path d="M65 64l10 4-5 3 2 7-3 1-2-7-4 3z" fill="#183e59" stroke="#fff" stroke-width="1.4" stroke-linejoin="round"/>
    <circle cx="82" cy="70" r="11" fill="#fff" stroke="#c8e4ed"/>
    <path d="M77 70h9m-3-4 4 4-4 4" fill="none" stroke="#2198bb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  `,
  realmA: (p) => `
    <ellipse cx="49" cy="84" rx="35" ry="6" fill="#3853aa" opacity=".12"/>
    <g filter="url(#${p}-shadow)">
      <path d="M24 16l14-6h34l8 7v53l-14 9H24z" fill="#bad0ff"/>
      <path d="M66 20l14-3v53l-14 9z" fill="#749beb"/>
      <rect x="24" y="20" width="42" height="59" rx="5" fill="url(#${p}-primary)"/>
    </g>
    <rect x="29" y="27" width="32" height="10" rx="3" fill="#e5edff"/>
    <rect x="29" y="42" width="32" height="10" rx="3" fill="#e5edff"/>
    <rect x="29" y="57" width="32" height="10" rx="3" fill="#e5edff"/>
    <circle cx="34" cy="32" r="1.8" fill="#4d77d8"/>
    <circle cx="34" cy="47" r="1.8" fill="#4d77d8"/>
    <circle cx="34" cy="62" r="1.8" fill="#4d77d8"/>
    <path d="M40 32h14M40 47h14M40 62h14" stroke="#acbfec" stroke-width="2" stroke-linecap="round"/>
    <path d="M69 37l19 7v14c0 12-8 20-19 25-11-5-19-13-19-25V44z" fill="#eef4ff" stroke="#5985db" stroke-width="2" filter="url(#${p}-shadow)"/>
    <path d="M60 64l9-19 9 19m-14-7h10" fill="none" stroke="#4270cd" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="22" cy="17" r="9" fill="#fff" stroke="#d9e4fc"/>
    <path d="M18 17l3 3 5-6" fill="none" stroke="#6b94eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  `,
  realmB: (p) => `
    <ellipse cx="50" cy="84" rx="35" ry="6" fill="#8653aa" opacity=".12"/>
    <g filter="url(#${p}-shadow)">
      <path d="M24 16l14-6h34l8 7v53l-14 9H24z" fill="#decbff"/>
      <path d="M66 20l14-3v53l-14 9z" fill="#aa80de"/>
      <rect x="24" y="20" width="42" height="59" rx="5" fill="url(#${p}-primary)"/>
    </g>
    <rect x="29" y="27" width="32" height="10" rx="3" fill="#f1eaff"/>
    <rect x="29" y="42" width="32" height="10" rx="3" fill="#f1eaff"/>
    <rect x="29" y="57" width="32" height="10" rx="3" fill="#f1eaff"/>
    <circle cx="34" cy="32" r="1.8" fill="#9564d4"/>
    <circle cx="34" cy="47" r="1.8" fill="#9564d4"/>
    <circle cx="34" cy="62" r="1.8" fill="#9564d4"/>
    <path d="M40 32h14M40 47h14M40 62h14" stroke="#c7afe9" stroke-width="2" stroke-linecap="round"/>
    <path d="M69 37l19 7v14c0 12-8 20-19 25-11-5-19-13-19-25V44z" fill="#faf5ff" stroke="#9b71d2" stroke-width="2" filter="url(#${p}-shadow)"/>
    <path d="M64 46v19h7c7 0 7-9 0-9h-7m0-10h6c7 0 7 10 0 10" fill="none" stroke="#8956c5" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="22" cy="17" r="9" fill="#fff" stroke="#e7dafb"/>
    <circle cx="20" cy="15" r="2.4" fill="none" stroke="#a080d4" stroke-width="1.8"/>
    <path d="M22 17l4 4m-2-2 1-1" stroke="#a080d4" stroke-width="1.8" stroke-linecap="round"/>
  `,
  external: (p) => `
    <ellipse cx="50" cy="85" rx="35" ry="7" fill="#24677a" opacity=".15"/>
    <path d="M24 68c-12 0-18-8-18-18s8-17 18-18c3-14 13-22 26-22 15 0 25 10 27 22 11 0 19 8 19 18 0 11-8 18-20 18z" fill="url(#${p}-primary)" filter="url(#${p}-shadow)"/>
    <circle cx="47" cy="40" r="18" fill="#e9fcff" stroke="#257f9a" stroke-width="2"/>
    <ellipse cx="47" cy="40" rx="8" ry="18" fill="none" stroke="#41a1bb" stroke-width="1.5"/>
    <path d="M29 40h36M32 31h30M32 49h30" stroke="#41a1bb" stroke-width="1.5"/>
    <rect x="57" y="49" width="30" height="29" rx="7" fill="#f5ffff" stroke="#23829b" stroke-width="2"/>
    <path d="M65 49v-5a7 7 0 0 1 14 0v5" fill="none" stroke="#23829b" stroke-width="3"/>
    <circle cx="72" cy="61" r="3" fill="#23829b"/><path d="M72 63v6" stroke="#23829b" stroke-width="3" stroke-linecap="round"/>
  `,
  webapp: (p) => `
    <ellipse cx="50" cy="86" rx="34" ry="6" fill="#557bba" opacity=".15"/>
    <rect x="15" y="12" width="42" height="67" rx="7" fill="url(#${p}-primary)" filter="url(#${p}-shadow)"/>
    <rect x="21" y="22" width="30" height="11" rx="3" fill="#eaf0ff"/><rect x="21" y="40" width="30" height="11" rx="3" fill="#eaf0ff"/><rect x="21" y="58" width="30" height="11" rx="3" fill="#eaf0ff"/>
    <circle cx="27" cy="27" r="2" fill="#647dbf"/><circle cx="27" cy="45" r="2" fill="#647dbf"/><circle cx="27" cy="63" r="2" fill="#647dbf"/>
    <rect x="40" y="32" width="49" height="44" rx="6" fill="#eef5ff" stroke="#7088cc" stroke-width="2" filter="url(#${p}-shadow)"/>
    <path d="M40 43h49" stroke="#c7d6f5" stroke-width="2"/><circle cx="46" cy="38" r="1.5" fill="#7b96d4"/><circle cx="51" cy="38" r="1.5" fill="#7b96d4"/>
    <path d="m54 54-6 6 6 6m21-12 6 6-6 6m-11-13-5 15" fill="none" stroke="#6d77c0" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
  `,
  yubikey: (p) => `
    <ellipse cx="51" cy="85" rx="29" ry="6" fill="#a88534" opacity=".15"/>
    <g transform="rotate(-23 50 51)" filter="url(#${p}-shadow)">
      <path d="M38 8h25v22H38z" fill="#c3cbd4"/>
      <path d="M41 11h19v17H41z" fill="#eef1f5"/>
      <path d="M44 13h4v6h-4m9-6h4v6h-4" fill="#8c99ab"/>
      <path d="M35 28h31v51c0 9-7 14-15 14s-16-5-16-14z" fill="url(#${p}-primary)"/>
      <path d="M36 30h29v6H36" fill="#fff" opacity=".26"/>
      <circle cx="50.5" cy="54" r="10" fill="#b98022"/>
      <circle cx="50.5" cy="54" r="7.8" fill="#fbe2a2"/>
      <path d="M51 48c-4 0-6 4-4 8m5-6c-3 0-4 3-3 6m6-5c0 3-1 6-3 8" fill="none" stroke="#b68529" stroke-width="1.4" stroke-linecap="round"/>
      <circle cx="50.5" cy="80" r="5.1" fill="#fff8e5"/>
      <circle cx="50.5" cy="80" r="3.3" fill="#b18a36" opacity=".3"/>
    </g>
    <path d="M73 24c5 2 7 7 5 12m0-18c9 4 13 13 9 22" fill="none" stroke="#ddb75f" stroke-width="2.6" stroke-linecap="round" opacity=".75"/>
    <circle cx="23" cy="60" r="11" fill="#fff" stroke="#eddfa9"/>
    <path d="M23 55v8m-3-5 3-3 3 3" fill="none" stroke="#cba040" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  `,
  hello: (p) => `
    <ellipse cx="51" cy="85" rx="39" ry="6" fill="#2e8e86" opacity=".12"/>
    <g filter="url(#${p}-shadow)">
      <rect x="18" y="16" width="65" height="57" rx="7" fill="#284b54"/>
      <rect x="22" y="20" width="57" height="48" rx="3" fill="url(#${p}-primary)"/>
      <circle cx="51" cy="18" r="1.3" fill="#b1e0dc"/>
      <path d="M18 72h65l10 8c1 2-1 4-5 4H13c-4 0-6-2-4-4z" fill="#b5d4d4"/>
      <path d="M37 72h27l4 5H33z" fill="#82aaaa"/>
      <path d="M11 80h80" stroke="#dae9e9" stroke-width="2"/>
    </g>
    <path d="M35 36v-5h6M60 31h6v5M66 53v6h-6M41 59h-6v-6" fill="none" stroke="#b7fff2" stroke-width="2" stroke-linecap="round"/>
    <path d="M42 36c0-5 4-8 9-8s9 3 9 8v6c0 7-4 12-9 12s-9-5-9-12z" fill="#d9fff2" opacity=".94"/>
    <circle cx="46.5" cy="40" r="1.3" fill="#368779"/>
    <circle cx="55.5" cy="40" r="1.3" fill="#368779"/>
    <path d="M47 47c3 2 5 2 8-1" fill="none" stroke="#368779" stroke-width="1.7" stroke-linecap="round"/>
    <path d="M28 44h45" stroke="#fff" stroke-width="1.5" opacity=".65"/>
    <circle cx="81" cy="24" r="11" fill="#fff" stroke="#c8ece4"/>
    <path d="M76 24l4 4 6-8" fill="none" stroke="#39a594" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
  `,
  totp: (p) => `
    <ellipse cx="50" cy="89" rx="30" ry="6" fill="#298777" opacity=".12"/>
    <g filter="url(#${p}-shadow)">
      <rect x="22" y="7" width="56" height="84" rx="10" fill="#244a4f"/>
      <rect x="26" y="11" width="48" height="76" rx="7" fill="#edfdf6"/>
      <path d="M37 11h26v3a3 3 0 0 1-3 3H40a3 3 0 0 1-3-3z" fill="#244a4f"/>
      <rect x="32" y="22" width="36" height="13" rx="4" fill="url(#${p}-primary)"/>
      <path d="M39 27h16m-16 4h23" stroke="#dcfff3" stroke-width="1.8" stroke-linecap="round"/>
      <rect x="28" y="39" width="44" height="21" rx="4" fill="#d1f5e6"/>
      <g fill="none" stroke="#157c60" stroke-width="1.25" stroke-linecap="round">${totpDigits()}</g>
      <circle cx="50" cy="72" r="8" fill="none" stroke="#c4e8dc" stroke-width="2.6"/>
      <path d="M50 64a8 8 0 1 1-8 8" fill="none" stroke="#29b98a" stroke-width="2.6" stroke-linecap="round"/>
      <path d="M50 68v4l3 2" fill="none" stroke="#209776" stroke-width="1.6" stroke-linecap="round"/>
      <path d="M42 84h16" stroke="#afcebe" stroke-width="2" stroke-linecap="round"/>
    </g>
    <circle cx="80" cy="28" r="11" fill="#fff" stroke="#c9ece0"/>
    <path d="M80 21l6 3v4c0 4-2 7-6 9-4-2-6-5-6-9v-4z" fill="#4ace9f"/>
    <path d="M77 28l2 2 4-5" fill="none" stroke="#fff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
  `,
};

const palettes = {
  user: ['#f18aab', '#cf557e'],
  app: ['#9b8cf6', '#6483e6'],
  browser: ['#65d9e4', '#238fb7'],
  realmA: ['#7aa8ff', '#4a6ecc'],
  realmB: ['#c498ef', '#9160c5'],
  external: ['#7cdbeb', '#3998b1'],
  webapp: ['#a7b8fa', '#657bc8'],
  yubikey: ['#f6d478', '#d4a542'],
  hello: ['#58ccb5', '#318e91'],
  totp: ['#5ee7b5', '#1eac83'],
};

/** Each call gets a new defs namespace, including repeated actors in overlays. */
export function actorIllustration(id) {
  const actorId = Object.hasOwn(artwork, id) ? id : 'user';
  const prefix = `actor-art-${actorId}-${++illustrationSequence}`;
  const [light, dark] = palettes[actorId];
  return `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" role="presentation" focusable="false" class="actor-illustration">
    <defs>
      <linearGradient id="${prefix}-primary" x1="0" y1="0" x2=".8" y2="1" gradientUnits="objectBoundingBox">
        <stop stop-color="${light}"/><stop offset="1" stop-color="${dark}"/>
      </linearGradient>
      <linearGradient id="${prefix}-skin" x1="0" y1="0" x2=".6" y2="1">
        <stop stop-color="#ffd2ae"/><stop offset="1" stop-color="#efab8b"/>
      </linearGradient>
      <filter id="${prefix}-shadow" x="-35%" y="-25%" width="170%" height="175%" color-interpolation-filters="sRGB">
        <feGaussianBlur in="SourceAlpha" stdDeviation="2.4" result="soft"/>
        <feOffset in="soft" dx="0" dy="3" result="offset"/>
        <feFlood flood-color="#203753" flood-opacity=".13"/>
        <feComposite in2="offset" operator="in" result="shadow"/>
        <feMerge><feMergeNode in="shadow"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
    </defs>
    ${artwork[actorId](prefix)}
  </svg>`;
}
