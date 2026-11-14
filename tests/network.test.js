import test from 'node:test';
import assert from 'node:assert/strict';
import { parseIPv4,formatIPv4,parseIPv4Cidr,ipv4Details,planVLSM,parseIPv6,formatIPv6,parseIPv6Cidr,planIPv6 } from '../src/shared/network.js';

test('IPv4 unsigned conversion preserves the high bit and full 32-bit range',()=>{
  assert.equal(formatIPv4(parseIPv4('255.255.255.255')),'255.255.255.255');
  assert.equal(parseIPv4('255.255.255.255'),4294967295n);
  assert.equal(formatIPv4(parseIPv4('128.0.0.1')),'128.0.0.1');
  assert.equal(formatIPv4(0n),'0.0.0.0');
  assert.throws(()=>parseIPv4('256.1.1.1'),/Invalid IPv4/);
  assert.throws(()=>parseIPv4('1.2.3'),/Invalid IPv4/);
});

test('CIDR normalization, masks, broadcast, and host ranges are correct',()=>{
  assert.equal(parseIPv4Cidr('192.168.10.19/24').canonical,'192.168.10.0/24');
  assert.deepEqual(ipv4Details(parseIPv4('192.168.10.0'),24),{network:'192.168.10.0',prefix:24,mask:'255.255.255.0',total:'256',usable:'254',first:'192.168.10.1',last:'192.168.10.254',broadcast:'192.168.10.255',startInt:'3232238080',endInt:'3232238335'});
  assert.deepEqual([ipv4Details(parseIPv4('10.0.0.0'),31).usable,ipv4Details(parseIPv4('10.0.0.0'),31).first,ipv4Details(parseIPv4('10.0.0.0'),31).last],['2','10.0.0.0','10.0.0.1']);
  assert.deepEqual([ipv4Details(parseIPv4('10.0.0.7'),32).usable,ipv4Details(parseIPv4('10.0.0.7'),32).first,ipv4Details(parseIPv4('10.0.0.7'),32).broadcast],['1','10.0.0.7','10.0.0.7']);
  assert.throws(()=>parseIPv4Cidr('10.0.0.0/33'),/between/);
  assert.throws(()=>parseIPv4Cidr('10.0.0.0'),/CIDR/);
});

test('VLSM sorts largest first, fits exactly, and rejects exhausted space without partial results',()=>{
  const result=planVLSM('192.168.10.0/24',[{name:'small',hosts:30},{name:'large',hosts:100},{name:'exact',hosts:62}]);
  assert.deepEqual(result.allocations.map(a=>a.name),['large','exact','small']);
  assert.deepEqual(result.allocations.map(a=>`${a.network}/${a.prefix}`),['192.168.10.0/25','192.168.10.128/26','192.168.10.192/27']);
  for(let i=1;i<result.allocations.length;i++)assert.ok(BigInt(result.allocations[i-1].endInt)<BigInt(result.allocations[i].startInt),'VLSM allocations must not overlap');
  assert.equal(planVLSM('10.0.0.0/31',[{name:'Point to point',hosts:2}]).allocations[0].prefix,31);
  assert.throws(()=>planVLSM('10.0.0.0/25',[{name:'A',hosts:100},{name:'B',hosts:60}]),/Insufficient address space/);
  assert.throws(()=>planVLSM('10.0.0.0/24',[{name:'',hosts:2}]),/needs a name/);
});

test('IPv6 parsing and formatting canonicalize compressed and full forms',()=>{
  const addr='2001:db8:0:1::abcd';
  assert.equal(formatIPv6(parseIPv6(addr)),addr);
  assert.equal(formatIPv6(parseIPv6('::')),'::');
  assert.equal(formatIPv6(parseIPv6('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')),'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');
  assert.equal(parseIPv6Cidr('2001:db8:1234::9/48').canonical,'2001:db8:1234::/48');
  assert.throws(()=>parseIPv6('1::2::3'),/Invalid IPv6/);
  assert.throws(()=>parseIPv6Cidr('2001:db8::/129'),/between/);
});

test('IPv6 /48-to-/64 planner allocates consecutive BigInt ranges and detects exhaustion',()=>{
  const p=planIPv6('2001:db8:abcd::/48',64,['Engineering','Sales']);
  assert.deepEqual(p.allocations.map(a=>a.network),['2001:db8:abcd::/64','2001:db8:abcd:1::/64']);
  assert.equal(BigInt(p.allocations[1].startInt)-BigInt(p.allocations[0].startInt),1n<<64n);
  assert.throws(()=>planIPv6('2001:db8::/64',64,['A','B']),/exhausted/);
  assert.throws(()=>planIPv6('2001:db8::/48',40,['A']),/from \/48/);
});
