# vpngate-realprobe

VPNGate 节点**真实连通性**测试：用 sing-box 1.14+ 的用户态网络栈（`system: false`），
在无 tun、无 root、无 netns 的条件下真正建立 OpenVPN 隧道并通过 SOCKS5 验证出口 IP。

## 为什么需要它

TLS 握手成功 ≠ 节点可用。实测 164 台里 71 台 TLS 可连，但只有 38 台能真正出网，
握手法高估约 1.9 倍。

## 数据来源

- 节点列表：`http://x{n}.x{n}.client.api.vpngate2.jp/api/`（插件接口，200 条）
  - 容器：240B 头 + 20B salt + `RC4(key = SHA1(salt))` 密文，无 IV/AAD/tag
  - 明文：SoftEther Pack，40 列 × NumHosts 行
- 认证：所有节点共用同一套 ca/cert/key，账号 `vpn` / `vpn`

## 运行

```bash
python vpngate_plugin_list.py --out plugin_nodes.json
python run_all.py plugin_nodes.json --workers 8 --timeout 25 --out results.json
```

## 输出

`results.json` 每项含 `ip / port / country / ok / egress / sec`。
`egress` 是通过该节点访问 `api.ipify.org` 得到的真实出口 IP。
