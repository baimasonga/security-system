// Resumable direct uploads. The API authorizes and signs; bytes go straight from the browser to private object
// storage on a separate origin. An interrupted upload resumes from the parts storage already holds: the upload id is
// remembered per file (name, size, modification time) in this browser only, and the server is asked which parts
// arrived. Nothing secret is stored: an upload id alone grants nothing without the signed-in session or the
// submission secret.

const KEY = 'rokela-resume:';
const remember = (k, v) => {
  try {
    if (v) localStorage.setItem(KEY + k, v);
    else localStorage.removeItem(KEY + k);
  } catch {
    /* storage unavailable: uploads still work, they just cannot resume across reloads */
  }
};
const recall = (k) => {
  try {
    return localStorage.getItem(KEY + k);
  } catch {
    return null;
  }
};
export const fileKey = (scope, file) =>
  `${scope}:${file.webkitRelativePath || file.name}:${file.size}:${file.lastModified}`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * @param {object} o
 * @param {File} o.file
 * @param {string} o.resumeKey
 * @param {() => Promise<{upload_id: string, part_size: number, part_count: number}>} o.begin
 * @param {(id: string) => Promise<any>} o.status
 * @param {(id: string, nums: number[]) => Promise<{parts: Array<{part_number: number, url: string}>}>} o.sign
 * @param {(id: string) => Promise<any>} o.complete
 * @param {(p: {sent: number, total: number, resumed: boolean}) => void} [o.onProgress]
 */
export async function uploadFile(o) {
  const total = o.file.size;
  let session;
  let held = [];
  let resumed = false;
  const prior = recall(o.resumeKey);
  if (prior) {
    try {
      const st = await o.status(prior);
      if (st.status === 'uploading') {
        session = { upload_id: prior, part_size: st.part_size, part_count: st.part_count };
        held = st.uploaded_parts;
        resumed = true;
      }
    } catch {
      /* expired or unknown: start again */
    }
  }
  if (!session) {
    session = await o.begin();
    remember(o.resumeKey, session.upload_id);
  }
  const size = session.part_size;
  const bytesOf = (n) => Math.min(size, total - (n - 1) * size);
  let sent = held.reduce((s, n) => s + bytesOf(n), 0);
  o.onProgress?.({ sent, total, resumed });
  const missing = [];
  for (let n = 1; n <= session.part_count; n++) if (!held.includes(n)) missing.push(n);
  for (let i = 0; i < missing.length; i += 20) {
    const batch = missing.slice(i, i + 20);
    const signed = await o.sign(session.upload_id, batch);
    for (const p of signed.parts) {
      const blob = o.file.slice((p.part_number - 1) * size, p.part_number * size);
      for (let attempt = 1; ; attempt++) {
        try {
          const res = await fetch(p.url, {
            method: 'PUT',
            body: blob,
            credentials: 'omit',
            mode: 'cors',
          });
          if (!res.ok) throw new Error(`storage answered ${res.status}`);
          break;
        } catch (e) {
          if (attempt >= 4)
            throw new Error(
              `Upload interrupted (${e.message}). Choose the same file again to resume.`,
            );
          await sleep(500 * 2 ** attempt);
        }
      }
      sent += blob.size;
      o.onProgress?.({ sent, total, resumed });
    }
  }
  const done = await o.complete(session.upload_id);
  remember(o.resumeKey, null);
  return done;
}

// ---- tiny PDF writer for the document composer -----------------------------------------------------------
// Produces a standards-conforming text PDF (Helvetica, A4). The editable source is embedded as a PDF comment so a
// draft made here can be reopened and edited again; other PDFs are edited in the Rokela PDF Pro editor.

const b64 = (str) => {
  let s = '';
  for (const b of new TextEncoder().encode(str)) s += String.fromCharCode(b);
  return btoa(s);
};
const unb64 = (b) => new TextDecoder().decode(Uint8Array.from(atob(b), (c) => c.charCodeAt(0)));
const latin1 = (s) => s.replace(/[^\x20-\x7e\xa0-\xff\n]/g, '?');
const esc = (s) => s.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');

function wrap(text, width = 88) {
  const out = [];
  for (const para of text.split('\n')) {
    if (!para.trim()) {
      out.push('');
      continue;
    }
    let line = '';
    for (const word of para.split(/\s+/)) {
      if ((line + ' ' + word).trim().length > width) {
        out.push(line);
        line = word;
      } else line = (line + ' ' + word).trim();
    }
    out.push(line);
  }
  return out;
}

export function composePdf({ title, body }) {
  const lines = wrap(latin1(body));
  const perPage = 50;
  const pages = [];
  for (let i = 0; i < Math.max(1, lines.length); i += perPage)
    pages.push(lines.slice(i, i + perPage));
  const objects = [];
  const add = (s) => objects.push(s) && objects.length;
  add('<< /Type /Catalog /Pages 2 0 R >>');
  add('PAGES');
  add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
  const kids = [];
  pages.forEach((pageLines, index) => {
    const ops = [
      'BT',
      '/F1 16 Tf',
      '56 790 Td',
      `(${esc(latin1(title))}) Tj`,
      '/F1 11 Tf',
      '0 -28 Td',
      '14 TL',
    ];
    for (const l of pageLines) ops.push(`(${esc(l)}) '`);
    ops.push('ET', 'BT', '/F1 8 Tf', '56 30 Td', `(Page ${index + 1} of ${pages.length}) Tj`, 'ET');
    const stream = ops.join('\n');
    const content = add(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
    kids.push(
      add(
        `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents ${content} 0 R >>`,
      ),
    );
  });
  objects[1] = `<< /Type /Pages /Kids [${kids.map((k) => `${k} 0 R`).join(' ')}] /Count ${kids.length} >>`;
  const source = b64(JSON.stringify({ v: 1, title, body }));
  let out = `%PDF-1.7\n%\xe2\xe3\xcf\xd3\n%RokelaComposerSource:${source}\n`;
  const offsets = [];
  objects.forEach((o, i) => {
    offsets.push(out.length);
    out += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const xref = out.length;
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.map((n) => `${String(n).padStart(10, '0')} 00000 n \n`).join('')}`;
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  const bytes = new Uint8Array(out.length);
  for (let i = 0; i < out.length; i++) bytes[i] = out.charCodeAt(i) & 0xff;
  return bytes;
}

/** Recovers the composer source from a draft made by composePdf, or null for other PDFs. */
export function composerSource(bytes) {
  const head = new TextDecoder('latin1').decode(bytes.subarray(0, Math.min(bytes.length, 200_000)));
  const m = /%RokelaComposerSource:([A-Za-z0-9+/=]+)/.exec(head);
  if (!m) return null;
  try {
    const v = JSON.parse(unb64(m[1]));
    return typeof v.title === 'string' && typeof v.body === 'string' ? v : null;
  } catch {
    return null;
  }
}
