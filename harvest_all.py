#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""合并两个节点来源并去重

来源 A: 插件接口 http://x{n}.x{n}.client.api.vpngate2.jp/api/  (200 条, 需解密)
来源 B: 公开 API https://www.vpngate.net/api/iphone/            (~97 条, 含 OpenVPN 配置)

去重键: IP。同一 IP 优先用插件的 SslPorts, 没有则从 OpenVPN 配置的 remote 行取端口。

输出 combined_nodes.json:
  {ip, country, ssl_ports, source: plugin|csv|both, fqdn, score, sessions}
"""
import base64
import json
import re
import sys
import urllib.request

from vpngate_plugin_list import fetch_list, decode, txt, ssl_ports, first

UA = {'User-Agent': 'Mozilla/5.0'}
CSV_URL = 'https://www.vpngate.net/api/iphone/'


def fetch_csv():
    raw = urllib.request.urlopen(urllib.request.Request(
        CSV_URL, headers=UA), timeout=30).read().decode('utf-8', 'replace').splitlines()
    header = None
    out = []
    for line in raw:
        line = line.strip()
        if not line or line in ('*',):
            continue
        if line.startswith('#'):
            header = line.lstrip('#').split(',')
            continue
        if header is None:
            continue
        parts = line.split(',')
        if len(parts) < 15:
            continue
        d = dict(zip(header, parts))
        ip = d.get('IP', '')
        if ip.count('.') != 3:
            continue
        port = None
        cfg = d.get('OpenVPN_ConfigData_Base64', '')
        if cfg:
            try:
                text = base64.b64decode(cfg + '=' * (-len(cfg) % 4)).decode('utf-8', 'replace')
                m = re.search(r'^remote\s+\S+\s+(\d+)', text, re.M)
                if m:
                    port = int(m.group(1))
            except Exception:
                pass
        out.append({
            'ip': ip,
            'country': d.get('CountryShort', ''),
            'ssl_ports': [port] if port else [],
            'fqdn': d.get('HostName', ''),
            'score': int(d['Score']) if d.get('Score', '').isdigit() else 0,
            'sessions': int(d['NumVpnSessions']) if d.get('NumVpnSessions', '').isdigit() else 0,
        })
    return out


def main(out_path='combined_nodes.json', polls=1, interval=60):
    pset, cset = {}, {}
    for i in range(polls):
        recs, meta = decode(fetch_list())
        for r in recs:
            ip = txt(r['IP'])
            pset.setdefault(ip, {
                'ip': ip,
                'country': txt(r.get('CountryShort')),
                'ssl_ports': ssl_ports(r),
                'fqdn': txt(r.get('Fqdn')),
                'score': first(r, 'Score'),
                'sessions': first(r, 'NumClients'),
            })
        for n in fetch_csv():
            cset.setdefault(n['ip'], n)
        print(f'  poll {i+1}/{polls}: plugin={len(pset)} csv={len(cset)}')
        if i + 1 < polls:
            import time
            time.sleep(interval)

    merged = {}
    for ip, n in pset.items():
        n = dict(n)
        n['source'] = 'both' if ip in cset else 'plugin'
        merged[ip] = n
    for ip, n in cset.items():
        if ip in merged:
            continue
        n = dict(n)
        n['source'] = 'csv'
        merged[ip] = n

    nodes = sorted(merged.values(), key=lambda x: (not x['ssl_ports'], x['ip']))
    json.dump(nodes, open(out_path, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)

    with_port = [n for n in nodes if n['ssl_ports']]
    print(f'插件接口   : {len(pset):>3} 唯一 IP')
    print(f'公开 API   : {len(cset):>3} 唯一 IP')
    print(f'交集       : {len(set(pset) & set(cset)):>3}')
    print(f'并集(去重) : {len(nodes):>3}')
    print(f'有 SSL 端口: {len(with_port):>3}')
    print(f'  仅插件   : {sum(1 for n in nodes if n["source"]=="plugin"):>3}')
    print(f'  仅公开   : {sum(1 for n in nodes if n["source"]=="csv"):>3}')
    print(f'  两边都有 : {sum(1 for n in nodes if n["source"]=="both"):>3}')
    print(f'写出 {out_path}')


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('out', nargs='?', default='combined_nodes.json')
    ap.add_argument('--polls', type=int, default=1)
    ap.add_argument('--interval', type=float, default=60)
    a = ap.parse_args()
    main(a.out, a.polls, a.interval)
