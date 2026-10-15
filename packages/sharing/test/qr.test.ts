import jsQRModule from 'jsqr';

// jsqr ships CommonJS with a default export; normalize across loaders.
const jsQR = ((jsQRModule as unknown as { default?: unknown }).default ??
  jsQRModule) as unknown as (
  data: Uint8ClampedArray,
  w: number,
  h: number,
) => { data: string } | null;
import { describe, expect, it } from 'vitest';
import { encodeQr, qrSvg, rsRemainder } from '../src/index.ts';

function decode(text: string): string | undefined {
  const q = encodeQr(text);
  const s = 4;
  const dim = (q.size + 8) * s;
  const px = new Uint8ClampedArray(dim * dim * 4).fill(255);
  for (let y = 0; y < q.size; y++)
    for (let x = 0; x < q.size; x++)
      if (q.modules[y]![x])
        for (let dy = 0; dy < s; dy++)
          for (let dx = 0; dx < s; dx++) {
            const o = (((y + 4) * s + dy) * dim + (x + 4) * s + dx) * 4;
            px[o] = px[o + 1] = px[o + 2] = 0;
          }
  return jsQR(px, dim, dim)?.data;
}

describe('QR encoder', () => {
  it('matches the published Reed–Solomon example (HELLO WORLD, 1-M)', () => {
    expect(
      rsRemainder([32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17], 10),
    ).toEqual([196, 35, 39, 119, 235, 215, 231, 226, 93, 23]);
  });

  it('round-trips through an independent decoder for every supported version', () => {
    for (const len of [1, 14, 15, 26, 42, 62, 84, 106, 122, 152, 180, 213]) {
      const t = `https://rokela.example/l/${'aB3-_x'.repeat(40)}`.slice(0, len);
      expect(decode(t), `length ${len}`).toBe(t);
    }
    const versions = new Set(
      [14, 26, 42, 62, 84, 106, 122, 152, 180, 213].map((n) => encodeQr('x'.repeat(n)).version),
    );
    expect([...versions].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  });

  it('encodes UTF-8 and refuses text that does not fit', () => {
    expect(decode('https://rokela.example/l/ŋɔ-salone')).toBe('https://rokela.example/l/ŋɔ-salone');
    expect(() => encodeQr('x'.repeat(214))).toThrow('too long');
  });

  it('renders a standalone SVG that never embeds the encoded text', () => {
    const svg = qrSvg('https://rokela.example/l/<script>');
    expect(svg.startsWith('<?xml')).toBe(true);
    expect(svg).not.toContain('script');
    expect(svg).toContain('viewBox');
  });
});
