#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VPNGate 插件列表获取器 —— 绕过公开 API 的 100 条上限

原理（静态逆向所得，纯标准库实现）:
    1. GET http://x{n}.x{n}.client.api.vpngate2.jp/api/
       返回 "VPNGate Data File"（约 75 KB）
    2. 容器: [240B 头][20B salt][RC4(key=SHA1(salt)) 密文]
       无 IV / 无 AAD / 无 GCM tag
    3. 明文是 SoftEther Pack: 外层 6 个元素（data 为内层 Pack）
       内层 40 列 × NumHosts 行（列式存储）
    4. 每行含 IP / CountryShort / SslPorts / L2TP / OpenvpnUdpPorts 等 40 字段

公开 API https://www.vpngate.net/api/iphone/ 只给约 88~97 台，
本接口给 200 条（198 个唯一 IP），其中约 169 台带 SSL-VPN 端口。

用法:
    python vpngate_plugin_list.py
    python vpngate_plugin_list.py --probe
    python vpngate_plugin_list.py --out nodes.json --probe --concurrency 64
"""
import argparse
import concurrent.futures
import hashlib
import json
import socket
import ssl
import struct
import time
import urllib.request

UA = {'User-Agent': 'Mozilla/5.0'}
ENDPOINT = 'http://x{a}.x{a}.client.api.vpngate2.jp/api/'
HDR_LEN, SALT_LEN = 0xF0, 0x14


def rc4(key, data):
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray(len(data))
    for k, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[k] = b ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)


def parse_pack(buf):
    n = struct.unpack_from('>I', buf, 0)[0]
    off = 4
    items = {}
    for _ in range(n):
        name_len = struct.unpack_from('>I', buf, off)[0]
        name = buf[off + 4:off + 4 + name_len - 1].decode('latin1')
        off += 4 + (name_len - 1)
        typ = struct.unpack_from('>I', buf, off)[0]
        count = struct.unpack_from('>I', buf, off + 4)[0]
        off += 8
        vals = []
        if typ == 0:
            vals = [struct.unpack_from('>I', buf, off + i * 4)[0] for i in range(count)]
            off += count * 4
        elif typ in (1, 2, 3):
            for _i in range(count):
                sl = struct.unpack_from('>I', buf, off)[0]
                off += 4
                vals.append(buf[off:off + sl])
                off += sl
        elif typ == 4:
            vals = [struct.unpack_from('>Q', buf, off + i * 8)[0] for i in range(count)]
            off += count * 8
        else:
            raise ValueError(f'unknown pack type {typ} for {name!r}')
        items[name] = {'type': typ, 'count': count, 'values': vals}
    return items, off


def fetch_list(timeout=30):
    last = None
    for a in '0123456789abcdefxyz':
        try:
            blob = urllib.request.urlopen(
                urllib.request.Request(ENDPOINT.format(a=a), headers=UA),
                timeout=timeout).read()
            if blob[:19] == b'[VPNGate Data File]':
                return blob
        except Exception as e:
            last = e
    raise SystemExit(f'所有镜像均失败: {last}')


def decode(blob):
    salt = blob[HDR_LEN:HDR_LEN + SALT_LEN]
    ct = blob[HDR_LEN + SALT_LEN:]
    key = hashlib.sha1(salt).digest()
    pt = rc4(key, ct)
    outer, _ = parse_pack(pt)
    inner_raw = outer['data']['values'][0]
    if inner_raw[:2] in (b'\x78\x9c', b'\x78\xda', b'\x78\x01'):
        import zlib
        inner_raw = zlib.decompress(inner_raw)
    inner, _ = parse_pack(inner_raw)
    n = inner['NumHosts']['values'][0] if 'NumHosts' in inner else None
    cols = {k: v['values'] for k, v in inner.items() if n and v['count'] == n}
    recs = [{k: cols[k][i] for k in cols} for i in range(n or 0)]
    return recs, {'salt': salt.hex(), 'key': key.hex(), 'num_hosts': n,
                  'columns': len(cols), 'plaintext_len': len(pt)}


def txt(v):
    if isinstance(v, (bytes, bytearray)):
        try:
            return v.decode('utf-8').rstrip('\x00')
        except Exception:
            return v.decode('latin1').rstrip('\x00')
    return v


def ssl_ports(rec):
    return [int(x) for x in txt(rec.get('SslPorts') or b'').replace(',', ' ').split()
            if x.strip().isdigit()]


def first(rec, k, default=0):
    v = rec.get(k)
    return v[0] if isinstance(v, list) and v else default


def probe(rec, timeout=6):
    ports = ssl_ports(rec)
    if not ports:
        return None
    ip, port = txt(rec['IP']), ports[0]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t0 = time.time()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            with ctx.wrap_socket(s) as ts:
                der = ts.getpeercert(binary_form=True)
        return {'ip': ip, 'port': port, 'alive': True,
                'rtt_ms': round((time.time() - t0) * 1000), 'cert_len': len(der)}
    except Exception as e:
        return {'ip': ip, 'port': port, 'alive': False, 'rtt_ms': None,
                'err': type(e).__name__}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='plugin_nodes.json')
    ap.add_argument('--probe', action='store_true')
    ap.add_argument('--concurrency', type=int, default=48)
    ap.add_argument('--timeout', type=float, default=6.0)
    a = ap.parse_args()

    blob = fetch_list()
    recs, meta = decode(blob)
    print(f'download  : {len(blob)} B')
    print(f'salt/key  : {meta["salt"][:16]}... / {meta["key"][:16]}...')
    print(f'NumHosts  : {meta["num_hosts"]}   columns: {meta["columns"]}')
    print(f'unique IP : {len({txt(r["IP"]) for r in recs})}')

    ssl_recs = [r for r in recs if ssl_ports(r)]
    print(f'SSL-VPN   : {len(ssl_recs)}')

    nodes = []
    for r in recs:
        nodes.append({
            'ip': txt(r['IP']),
            'country': txt(r.get('CountryShort')),
            'fqdn': txt(r.get('Fqdn')),
            'ssl_ports': ssl_ports(r),
            'l2tp': bool(first(r, 'L2TP')),
            'udp_port': first(r, 'UdpPort'),
            'score': first(r, 'Score'),
            'sessions': first(r, 'NumClients'),
            'owner': txt(r.get('Owner')) if r.get('Owner') else '',
        })

    if a.probe:
        print(f'\nprobing (conc={a.concurrency}, timeout={a.timeout}s)...')
        t0 = time.time()
        with concurrent.futures.ThreadPoolExecutor(a.concurrency) as ex:
            results = list(ex.map(lambda r: probe(r, a.timeout), ssl_recs))
        alive = [x for x in results if x and x['alive']]
        print(f'alive     : {len(alive)} / {len(ssl_recs)}  ({time.time()-t0:.1f}s)')
        amap = {x['ip']: x for x in alive}
        for n in nodes:
            p = amap.get(n['ip'])
            n['alive'] = bool(p)
            if p:
                n['rtt_ms'] = p['rtt_ms']
        nodes.sort(key=lambda x: (not x.get('alive'), x.get('rtt_ms') or 1e9))
        for f in sorted(alive, key=lambda x: x['rtt_ms'])[:5]:
            print(f'   {f["ip"]}:{f["port"]:<5} {f["rtt_ms"]:>5}ms')

    json.dump(nodes, open(a.out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(f'\nwrote {len(nodes)} -> {a.out}')


if __name__ == '__main__':
    main()
