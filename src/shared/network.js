const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function parseIPv4(text) {
  const m = IPV4_RE.exec(String(text).trim());
  if (!m) throw new Error(`Invalid IPv4 address: ${text}`);
  const octets = m.slice(1).map(Number);
  if (octets.some(n => n > 255)) throw new Error(`Invalid IPv4 address: ${text}`);
  return octets.reduce((value, octet) => value * 256n + BigInt(octet), 0n);
}

export function formatIPv4(value) {
  if (typeof value !== 'bigint' || value < 0n || value > 0xffffffffn) throw new Error('IPv4 integer is out of range');
  return [24n, 16n, 8n, 0n].map(s => Number((value >> s) & 255n)).join('.');
}

export function parseIPv4Cidr(text) {
  const m = /^(.*)\/(\d{1,2})$/.exec(String(text).trim());
  if (!m) throw new Error('Enter an IPv4 network in CIDR notation, such as 192.168.10.0/24.');
  const prefix = Number(m[2]);
  if (prefix < 0 || prefix > 32) throw new Error('IPv4 prefix must be between /0 and /32.');
  const address = parseIPv4(m[1]);
  const size = 1n << BigInt(32 - prefix);
  const network = (address / size) * size;
  return { network, prefix, size, end: network + size - 1n, canonical: `${formatIPv4(network)}/${prefix}` };
}

export function ipv4Details(network, prefix) {
  const size = 1n << BigInt(32 - prefix);
  const mask = prefix === 0 ? 0n : (0xffffffffn << BigInt(32 - prefix)) & 0xffffffffn;
  const broadcast = network + size - 1n;
  const usable = prefix === 32 ? 1n : prefix === 31 ? 2n : size - 2n;
  const first = prefix >= 31 ? network : network + 1n;
  const last = prefix >= 31 ? broadcast : broadcast - 1n;
  return { network: formatIPv4(network), prefix, mask: formatIPv4(mask), total: size.toString(), usable: usable.toString(), first: formatIPv4(first), last: formatIPv4(last), broadcast: formatIPv4(broadcast), startInt: network.toString(), endInt: broadcast.toString() };
}

export function planVLSM(cidr, requirements) {
  const base = parseIPv4Cidr(cidr);
  if (!Array.isArray(requirements) || requirements.length === 0) throw new Error('Add at least one named subnet requirement.');
  const parsed = requirements.map((r, i) => {
    const name = String(r.name ?? '').trim();
    const hosts = Number(r.hosts);
    if (!name || name.length > 80) throw new Error(`Subnet ${i + 1} needs a name of 1–80 characters.`);
    if (!Number.isSafeInteger(hosts) || hosts < 1) throw new Error(`${name}: host requirement must be a positive whole number.`);
    const prefix = hosts === 1 ? 32 : hosts === 2 ? 31 : Math.max(0, 32 - Math.ceil(Math.log2(hosts + 2)));
    if (prefix < 0) throw new Error(`${name}: requirement is too large for IPv4.`);
    return { name, hosts, prefix, size: 1n << BigInt(32 - prefix) };
  }).sort((a, b) => b.hosts - a.hosts || a.name.localeCompare(b.name));
  let cursor = base.network;
  const allocations = [];
  for (const item of parsed) {
    const aligned = ((cursor + item.size - 1n) / item.size) * item.size;
    const end = aligned + item.size - 1n;
    if (aligned < base.network || end > base.end) throw new Error(`Insufficient address space: ${item.name} (${item.hosts} hosts) does not fit inside ${base.canonical}. No partial plan was created.`);
    allocations.push({ name: item.name, requiredHosts: item.hosts, ...ipv4Details(aligned, item.prefix) });
    cursor = end + 1n;
  }
  return { family: 4, base: base.canonical, allocations };
}

const MAX128 = (1n << 128n) - 1n;
export function parseIPv6(text) {
  let input = String(text).trim().toLowerCase();
  if (!input || input.includes('%')) throw new Error(`Invalid IPv6 address: ${text}`);
  if (input.includes('.')) throw new Error('IPv4-embedded IPv6 notation is not supported. Use hexadecimal groups.');
  if ((input.match(/::/g) || []).length > 1) throw new Error(`Invalid IPv6 address: ${text}`);
  const compressed = input.includes('::');
  const [leftText, rightText = ''] = compressed ? input.split('::') : [input, ''];
  const left = leftText ? leftText.split(':') : [];
  const right = rightText ? rightText.split(':') : [];
  if ([...left, ...right].some(g => !/^[0-9a-f]{1,4}$/.test(g))) throw new Error(`Invalid IPv6 address: ${text}`);
  let groups;
  if (compressed) {
    const zeros = 8 - left.length - right.length;
    if (zeros < 1) throw new Error(`Invalid IPv6 address: ${text}`);
    groups = [...left, ...Array(zeros).fill('0'), ...right];
  } else {
    groups = left;
    if (groups.length !== 8) throw new Error(`Invalid IPv6 address: ${text}`);
  }
  return groups.reduce((v, group) => (v << 16n) | BigInt(`0x${group}`), 0n);
}

export function formatIPv6(value) {
  if (typeof value !== 'bigint' || value < 0n || value > MAX128) throw new Error('IPv6 integer is out of range');
  const groups = Array.from({ length: 8 }, (_, i) => Number((value >> BigInt((7 - i) * 16)) & 0xffffn).toString(16));
  let bestStart = -1, bestLength = 1;
  for (let i = 0; i < 8;) {
    if (groups[i] !== '0') { i++; continue; }
    let j = i; while (j < 8 && groups[j] === '0') j++;
    if (j - i > bestLength) { bestStart = i; bestLength = j - i; }
    i = j;
  }
  if (bestStart < 0) return groups.join(':');
  const before = groups.slice(0, bestStart).join(':');
  const after = groups.slice(bestStart + bestLength).join(':');
  return `${before}::${after}`;
}

export function parseIPv6Cidr(text) {
  const m = /^(.*)\/(\d{1,3})$/.exec(String(text).trim());
  if (!m) throw new Error('Enter an IPv6 prefix in CIDR notation, such as 2001:db8:1200::/48.');
  const prefix = Number(m[2]);
  if (prefix < 0 || prefix > 128) throw new Error('IPv6 prefix must be between /0 and /128.');
  const address = parseIPv6(m[1]);
  const size = 1n << BigInt(128 - prefix);
  const network = (address / size) * size;
  return { network, prefix, size, end: network + size - 1n, canonical: `${formatIPv6(network)}/${prefix}` };
}

export function planIPv6(cidr, subnetPrefix, names) {
  const base = parseIPv6Cidr(cidr);
  const prefix = Number(subnetPrefix);
  if (!Number.isInteger(prefix) || prefix < base.prefix || prefix > 128) throw new Error(`Subnet prefix must be an integer from /${base.prefix} through /128.`);
  if (!Array.isArray(names) || names.length < 1) throw new Error('Add at least one subnet name.');
  if (names.length > 65536) throw new Error('A single plan can contain at most 65,536 IPv6 allocations.');
  const size = 1n << BigInt(128 - prefix);
  const count = 1n << BigInt(prefix - base.prefix);
  if (BigInt(names.length) > count) throw new Error(`Address space exhausted: ${base.canonical} contains ${count} /${prefix} subnets, but ${names.length} were requested.`);
  const allocations = names.map((raw, i) => {
    const name = String(raw).trim();
    if (!name || name.length > 80) throw new Error(`Subnet ${i + 1} needs a name of 1–80 characters.`);
    const network = base.network + BigInt(i) * size;
    return { name, network: `${formatIPv6(network)}/${prefix}`, startInt: network.toString(), endInt: (network + size - 1n).toString(), total: size.toString() };
  });
  return { family: 6, base: base.canonical, subnetPrefix: prefix, allocations };
}
