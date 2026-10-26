// Tiny synthetic MMDB: every IPv4 maps to US. Never production geolocation data.
export function countryFixture(built = new Date('2026-10-01T00:00:00Z')) {
  const string = (value: string) =>
    Buffer.concat([Buffer.from([64 + value.length]), Buffer.from(value)]);
  const number = (value: number) => {
    const bytes = Buffer.alloc(4);
    bytes.writeUInt32BE(value);
    return Buffer.concat([Buffer.from([196]), bytes]);
  };
  const map = (entries: Array<[string, Buffer]>) =>
    Buffer.concat([
      Buffer.from([224 + entries.length]),
      ...entries.flatMap(([key, value]) => [string(key), value]),
    ]);
  const data = map([['country', map([['iso_code', string('US')]])]]);
  const metadata = map([
    ['node_count', number(1)],
    ['record_size', number(24)],
    ['ip_version', number(4)],
    ['database_type', string('DBIP-Country-Lite')],
    ['build_epoch', number(+built / 1000)],
    ['binary_format_major_version', number(2)],
    ['binary_format_minor_version', number(0)],
  ]);
  return Buffer.concat([
    Buffer.from([0, 0, 17, 0, 0, 17]),
    Buffer.alloc(16),
    data,
    Buffer.from('ABCDEF4D61784D696E642E636F6D', 'hex'),
    metadata,
  ]);
}
