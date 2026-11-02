#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VPNGate 节点无特权实连测试（sing-box 用户态栈，无 tun / 无 root）

用法:
    python run_all.py plugin_nodes.json --workers 12 --timeout 35 --out results.json
    python run_all.py plugin_nodes.json --plugin-only      # 只测公开 API 拿不到的那批
"""
import argparse
import base64
import concurrent.futures
import json
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request

UA = {'User-Agent': 'Mozilla/5.0'}
HERE = os.path.dirname(os.path.abspath(__file__))


def find_singbox():
    import glob
    pats = [
        os.path.join(HERE, 'sing-box', 'sing-box'),
        os.path.join(HERE, 'sing-box-*-linux-amd64', 'sing-box'),
        os.path.join(HERE, 'sing-box-*-windows-amd64', 'sing-box.exe'),
    ]
    for p in pats:
        for hit in sorted(glob.glob(p)):
            if os.path.isfile(hit):
                return hit
    import shutil
    return shutil.which('sing-box')


SB = find_singbox()
PRINT_LOCK = threading.Lock()


def fetch_shared_certs():
    raw = urllib.request.urlopen(urllib.request.Request(
        'https://www.vpngate.net/api/iphone/', headers=UA), timeout=30
    ).read().decode('utf-8', 'replace').splitlines()
    for line in raw[2:]:
        p = line.split(',')
        if len(p) > 14 and p[1].count('.') == 3:
            cfg = base64.b64decode(p[14] + '=' * (-len(p[14]) % 4)).decode('utf-8', 'replace')
            def blk(tag):
                m = re.search(rf'<{tag}>(.*?)</{tag}>', cfg, re.S)
                return [x for x in m.group(1).strip().splitlines() if x.strip()]
            ca, cert, key = blk('ca'), blk('cert'), blk('key')
            if ca and cert and key:
                return ca, cert, key
    raise SystemExit('无法提取证书')


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def build_config(ip, port, ca, cert, key, socks_port):
    return {
        'log': {'level': 'warn'},
        'inbounds': [{'type': 'mixed', 'tag': 'in', 'listen': '127.0.0.1',
                      'listen_port': socks_port}],
        'endpoints': [{
            'type': 'openvpn-client', 'tag': 'vg',
            'server': ip, 'server_port': int(port),
            'network': 'tcp', 'system': False,
            'username': 'vpn', 'password': 'vpn',
            'tls': {'certificate': ca, 'client_certificate': cert,
                    'client_key': key, 'remote_certificate_tls': 'none'},
            'data_ciphers': ['AES-128-CBC'], 'auth': 'SHA1',
            'route_no_pull': True, 'ping_restart_disabled': True,
        }],
        'route': {'rules': [{'inbound': 'in', 'outbound': 'vg'}]},
    }


def probe_one(node, ca, cert, key, timeout):
    ip, port = node['ip'], node['ssl_ports'][0]
    socks = free_port()
    tag = f'{ip}_{port}'
    cfg_path = os.path.join(tempfile.gettempdir(), f'sb_{tag}.json')
    log_path = os.path.join(tempfile.gettempdir(), f'sb_{tag}.log')
    json.dump(build_config(ip, port, ca, cert, key, socks), open(cfg_path, 'w'), indent=1)
    t0 = time.time()
    proc = subprocess.Popen(
        [SB, 'run', '-c', cfg_path],
        stdout=open(log_path, 'w'), stderr=subprocess.STDOUT,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
    )
    egress = None
    err = 'timeout'
    try:
        deadline = t0 + timeout
        while time.time() < deadline:
            time.sleep(0.4)
            if proc.poll() is not None:
                err = 'sing-box exited'
                break
            try:
                with socket.create_connection(('127.0.0.1', socks), timeout=1):
                    pass
            except Exception:
                continue
            r = subprocess.run(
                ['curl', '-s', '--socks5-hostname', f'127.0.0.1:{socks}',
                 '-m', '10', 'https://api.ipify.org'],
                capture_output=True, text=True, timeout=16)
            e = r.stdout.strip()
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', e):
                egress = e
                break
    except Exception as e:
        err = f'{type(e).__name__}'
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=4)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    el = round(time.time() - t0, 1)
    if egress:
        return {'ip': ip, 'port': port, 'country': node.get('country'),
                'ok': True, 'egress': egress, 'sec': el}
    tail = ''
    try:
        s = re.sub(r'\x1b\[[0-9;]*m', '', open(log_path, encoding='utf-8', errors='replace').read())
        bad = [l for l in s.splitlines()
               if 'ERROR' in l and 'not ready' not in l]
        tail = bad[-1][:160] if bad else (s.splitlines()[-1][:160] if s.strip() else '')
    except Exception:
        pass
    return {'ip': ip, 'port': port, 'country': node.get('country'),
            'ok': False, 'err': err, 'sec': el, 'log': tail}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('nodes')
    ap.add_argument('--workers', type=int, default=12)
    ap.add_argument('--timeout', type=float, default=35)
    ap.add_argument('--limit', type=int, default=0)
    ap.add_argument('--plugin-only', action='store_true')
    ap.add_argument('--out', default='results.json')
    a = ap.parse_args()

    nodes = json.load(open(a.nodes, encoding='utf-8'))
    cand = [n for n in nodes if n.get('ssl_ports')]
    if a.plugin_only:
        cmp_path = os.path.join(HERE, 'ip_cmp.json')
        if os.path.exists(cmp_path):
            csv_ips = set(json.load(open(cmp_path))['csv'])
            cand = [n for n in cand if n['ip'] not in csv_ips]
    if a.limit:
        cand = cand[:a.limit]

    ca, cert, key = fetch_shared_certs()
    print(f'证书 CA {len(ca)} / CERT {len(cert)} / KEY {len(key)} 行')
    print(f'待测 {len(cand)} 台，并发 {a.workers}，单台超时 {a.timeout}s\n')

    results = []
    done = 0
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(a.workers) as ex:
        futs = {ex.submit(probe_one, n, ca, cert, key, a.timeout): n for n in cand}
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            results.append(r)
            done += 1
            if r['ok']:
                msg = f"OK   {r['ip']}:{r['port']:<5} {r['country']} egress={r['egress']} {r['sec']}s"
            else:
                msg = f"FAIL {r['ip']}:{r['port']:<5} {r['country']} {r['err']} {r['sec']}s"
            with PRINT_LOCK:
                print(f'[{done:>3}/{len(cand)}] {msg}')

    ok = [r for r in results if r['ok']]
    print(f'\n{"="*66}')
    print(f'测试总数   : {len(results)}')
    print(f'真正可用   : {len(ok)}  ({len(ok)/max(1,len(results))*100:.1f}%)')
    print(f'耗时       : {round(time.time()-t0,1)}s')
    if ok:
        by_cc = {}
        for r in ok:
            by_cc[r['country']] = by_cc.get(r['country'], 0) + 1
        print('可用国家   :', sorted(by_cc.items(), key=lambda x: -x[1])[:10])
        print('出口 IP 与节点 IP 不同的:',
              sum(1 for r in ok if r['egress'] != r['ip']), '/', len(ok))
    json.dump(results, open(a.out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(f'结果写入   : {a.out}')


if __name__ == '__main__':
    main()
