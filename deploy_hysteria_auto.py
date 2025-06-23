#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deploy_hysteria_auto.py

—— 单文件版 ——
运行时仅需 deploy_hysteria_auto.py（可打包成 EXE 双击运行）：
1. 提示输入服务器 IP、SSH 端口和密码（明文可见）。
2. 提示输入实例数量。
3. SSH 上传并执行内嵌的 Bash 脚本 (/tmp/install.sh)。
4. 实时在本地控制台打印远程执行日志，并写入本地 install.log。
5. 脚本自动完成：
   • 复制自身到 /usr/local/bin/hysteria2-bootstrap.sh
   • 安装依赖、清理旧环境、部署 Hysteria2 多实例
   • 写入带 ExecStartPre 延时的 systemd 单元并启用
6. 安装完成后，本地生成 clash_subscription_{IP}.txt。
"""
import paramiko
import sys

BASH_SCRIPT = r'''#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractive

# ===== Self-install into /usr/local/bin automatically =====
TARGET="/usr/local/bin/hysteria2-bootstrap.sh"
if command -v realpath >/dev/null 2>&1; then
  SELF="$(realpath "$0")"
else
  cd "$(dirname "$0")"; SELF="$(pwd)/$(basename "$0")"
fi
if [[ "$SELF" != "$TARGET" ]]; then
  mkdir -p "$(dirname "$TARGET")"
  cp "$SELF" "$TARGET"
  chmod +x "$TARGET"
  echo "Installed to $TARGET, now re-running..."
  exec "$TARGET" "$@"
fi
SCRIPT_PATH="$TARGET"

# ===== 1. Install dependencies if missing =====
REQUIRED_PKGS=(iproute2 iptables iptables-persistent nginx curl openssl)
install_list=()
for pkg in "${REQUIRED_PKGS[@]}"; do
  if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
    install_list+=("$pkg")
  fi
done
if [ ${#install_list[@]} -gt 0 ]; then
  apt-get update -qq
  apt-get install -qq -y "${install_list[@]}"
fi

# ===== 2. Cleanup stage =====
ip netns list | awk '{print $1}' | xargs -r -n1 ip netns del 2>/dev/null || true
ip -o link show | awk -F': ' '/veth-/{print $2}' | cut -d@ -f1 \
  | xargs -r -n1 ip link del 2>/dev/null || true
old_svcs=$(systemctl list-unit-files --type=service \
  | awk '/^hysteria2_.*\.service$/ {print $1}')
if [ -n "$old_svcs" ]; then
  systemctl stop $old_svcs 2>/dev/null || true
  systemctl disable $old_svcs 2>/dev/null || true
fi
pkill -f /etc/hysteria2/hysteria 2>/dev/null || true
rm -f /etc/systemd/system/hysteria2_*.service \
      /etc/systemd/system/multi-user.target.wants/hysteria2_*.service
systemctl daemon-reload
iptables -t nat -S | grep '10\.10\.' | grep -E 'POSTROUTING|PREROUTING' \
  | sed 's/^-A //' | while read -r r; do iptables -t nat -D $r 2>/dev/null; done
iptables -S FORWARD | grep '10\.10\.' | sed 's/^-A //' \
  | while read -r r; do iptables -D $r 2>/dev/null; done

# ===== 3. Deploy stage =====
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || \
  echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
iptables -t nat -C POSTROUTING -s 10.10.0.0/16 -j MASQUERADE \
  >/dev/null 2>&1 && iptables -t nat -D POSTROUTING -s 10.10.0.0/16 \
  -j MASQUERADE >/dev/null 2>&1

# Detect public IPs
mapfile -t ALL_IPS < <(ip -4 addr show \
  | awk '/inet /{sub(/\/.*/,"",$2); print $2}' \
  | grep -Ev '^(10\.|172\.|192\.168\.|127\.)')
PUBIP_NUM=${#ALL_IPS[@]}
[ $PUBIP_NUM -gt 0 ] || { echo "未检测到公网IP"; exit 1; }

# Read desired instance count
INSTANCE_NUM_FILE="/tmp/.hysteria_instance_count"
if [[ -f "$INSTANCE_NUM_FILE" ]]; then
  INSTANCE_NUM=$(cat "$INSTANCE_NUM_FILE")
  rm -f "$INSTANCE_NUM_FILE"
else
  INSTANCE_NUM=$PUBIP_NUM
fi

# 计算实例的IP分配（循环或一一对应）
declare -a IPS PORTS PASSWORDS
for ((i=0; i<INSTANCE_NUM; i++)); do
  idx=$(( PUBIP_NUM > 0 ? i % PUBIP_NUM : 0 ))
  IPS[i]="${ALL_IPS[$idx]}"
  while :; do
    p=$((RANDOM%40000+20000))
    ss -lunt | grep -q ":$p " || { PORTS[i]=$p; break; }
  done
  PASSWORDS[i]="$(tr -dc 'A-Za-z0-9' </dev/urandom|head -c16)"
done

# ===== 端口自动放行（iptables、ufw、firewalld）=====
for ((i=0; i<INSTANCE_NUM; i++)); do
  port="${PORTS[$i]}"
  iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport "$port" -j ACCEPT
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "$port"/udp || true
  fi
  if systemctl is-active firewalld >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$port"/udp || true
    firewall-cmd --reload || true
  fi
done

H_URL=https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64
mkdir -p /etc/hysteria2 && cd /etc/hysteria2
wget -qO hysteria "$H_URL" && chmod +x hysteria
if [[ ! -f hysteria.key || ! -f hysteria.crt ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout hysteria.key -out hysteria.crt \
    -days 3650 -subj '/CN=multiip'
fi

mkdir -p /var/www/html
systemctl enable nginx; systemctl restart nginx

for ((i=0; i<INSTANCE_NUM; i++)); do
  ip_pub="${IPS[$i]}" port="${PORTS[$i]}" pw="${PASSWORDS[$i]}"
  ns="ns$((i+1))" vip="10.10.$((i+1)).1" nip="10.10.$((i+1)).2"
  vh="veth-${ns}-br"; vn="veth-${ns}"

  ip netns add "$ns"
  ip link add "$vn" type veth peer name "$vh"
  ip link set "$vn" netns "$ns"
  ip addr add ${ip_pub}/32 dev "$vh"
  ip addr add ${vip}/30 dev "$vh"
  ip link set "$vh" up

  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip link set dev "$vn" up
  ip netns exec "$ns" ip addr add ${nip}/30 dev "$vn"
  ip netns exec "$ns" ip route add default via $vip dev "$vn"

  iptables -t nat -C POSTROUTING -s ${nip}/32 -j SNAT --to-source $ip_pub \
    || iptables -t nat -A POSTROUTING -s ${nip}/32 -j SNAT --to-source $ip_pub
  iptables -t nat -C PREROUTING -d ${ip_pub}/32 -p udp --dport $port \
    -j DNAT --to-destination ${nip}:$port \
    || iptables -t nat -A PREROUTING -d ${ip_pub}/32 -p udp --dport $port \
         -j DNAT --to-destination ${nip}:$port
  iptables -C FORWARD -p udp -d ${nip}/32 --dport $port -j ACCEPT \
    || iptables -A FORWARD -p udp -d ${nip}/32 --dport $port -j ACCEPT

  cat > /etc/hysteria2/hysteria2_server_${ip_pub}_${port}.yaml <<EOF
listen: "0.0.0.0:${port}"
tls:
  cert: /etc/hysteria2/hysteria.crt
  key: /etc/hysteria2/hysteria.key
auth:
  type: password
  password: ${pw}
masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true
EOF

  cat > /etc/systemd/system/hysteria2_${ip_pub}_${port}.service <<EOF
[Unit]
Description=Hysteria2 Server for ${ip_pub}:${port}
After=hysteria2-bootstrap.service network.target

[Service]
Type=simple
ExecStart=/usr/sbin/ip netns exec ${ns} /etc/hysteria2/hysteria server -c /etc/hysteria2/hysteria2_server_${ip_pub}_${port}.yaml
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
done

systemctl daemon-reload
for ((i=0; i<INSTANCE_NUM; i++)); do
  ip="${IPS[$i]}" port="${PORTS[$i]}"
  systemctl enable hysteria2_${ip}_${port}
  systemctl restart hysteria2_${ip}_${port}
done

cat > /var/www/html/clash.yaml <<EOF
port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info

dns:
  enable: true
  listen: ':53'
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter-mode: blacklist
  fake-ip-filter:
    - '*.lan'
    - '*.local'
    - '*.arpa'
    - 'time.*.com'
    - 'ntp.*.com'
    - '+.market.xiaomi.com'
    - 'localhost.ptlogin2.qq.com'
    - '*.msftncsi.com'
    - 'www.msftconnecttest.com'
    - '*.msu.io'
  default-nameserver:
    - 'system'
    - '223.6.6.6'
    - '8.8.8.8'
  nameserver:
    - '8.8.8.8'
    - 'https://doh.pub/dns-query'
    - 'https://dns.alidns.com/dns-query'
  direct-nameserver-follow-policy: false
  fallback-filter:
    geoip: true
    geoip-code: 'CN'
    ipcidr:
      - '240.0.0.0/4'
      - '0.0.0.0/32'
    domain:
      - '+.google.com'
      - '+.facebook.com'
      - '+.youtube.com'
  proxy-server-nameserver:
    - 'https://doh.pub/dns-query'
    - 'https://dns.alidns.com/dns-query'
    - 'tls://223.5.5.5'

proxies:
EOF

for ((i=0; i<INSTANCE_NUM; i++)); do
  ip="${IPS[$i]}"
  port="${PORTS[$i]}"
  pw="${PASSWORDS[$i]}"
  seq=$((i+1))
  ip_dash="${ip//./-}"
  cat >> /var/www/html/clash.yaml <<EOF
  - name: "${seq}号-${ip_dash}-${port}"
    type: hysteria2
    server: ${ip}
    port: ${port}
    password: ${pw}
    sni: www.bing.com
    skip-cert-verify: true
    up: auto
    down: auto
    alpn: [h3]
    protocol: udp
EOF
done

cat >> /var/www/html/clash.yaml <<EOF

proxy-groups:
  - name: "Auto"
    type: select
    proxies:
EOF

for ((i=0; i<INSTANCE_NUM; i++)); do
  seq=$((i+1))
  ip_dash="${IPS[$i]//./-}"
  port="${PORTS[$i]}"
  echo "      - ${seq}号-${ip_dash}-${port}" >> /var/www/html/clash.yaml
done

cat >> /var/www/html/clash.yaml <<EOF

rules:
  - GEOIP,CN,DIRECT
  - MATCH,Auto
EOF

mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

cat > /etc/systemd/system/hysteria2-bootstrap.service <<EOF
[Unit]
Description=Hysteria2 一键部署 & 重建服务
After=network.target
Wants=network.target

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 5
ExecStart=${SCRIPT_PATH}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable hysteria2-bootstrap.service
'''

def main():
    server_ip = input("请输入服务器 IP: ").strip()
    port_str = input("请输入 SSH 端口（默认 22）：").strip() or "22"
    try:
        ssh_port = int(port_str)
    except:
        ssh_port = 22
    username = "root"
    password = input("请输入 SSH 密码（明文可见）：").strip()
    instance_num_str = input("请输入需要部署的实例数量（正整数，建议 ≤ 公网IP数时填公网IP数，否则填大于公网IP数的数）：").strip()
    try:
        instance_num = int(instance_num_str)
        if instance_num <= 0:
            print("实例数量必须为正整数。")
            sys.exit(1)
    except:
        print("实例数量输入有误。")
        sys.exit(1)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(server_ip, port=ssh_port, username=username, password=password, timeout=10)
    except Exception as e:
        print(f"SSH 连接失败: {e}")
        sys.exit(1)

    remote_path = "/tmp/install.sh"
    instance_file = "/tmp/.hysteria_instance_count"
    try:
        sftp = ssh.open_sftp()
        # 写入实例数量到远程临时文件，install.sh读取后自动删除
        with sftp.file(instance_file, "w") as ff:
            ff.write(str(instance_num))
        with sftp.file(remote_path, "w") as rf:
            rf.write(BASH_SCRIPT)
        sftp.chmod(remote_path, 0o755)
        sftp.close()
    except Exception as e:
        print(f"上传脚本失败: {e}")
        ssh.close()
        sys.exit(1)

    print("\n—— 开始远程执行安装脚本 ——\n")
    with open("install.log", "w", encoding="utf-8") as log_file:
        stdin, stdout, stderr = ssh.exec_command(f"bash {remote_path}", get_pty=True)
        for line in iter(stdout.readline, ""):
            print(line, end="")
            log_file.write(line)
        for line in iter(stderr.readline, ""):
            print(line, end="")
            log_file.write(line)

    print("\n—— 安装完成，详情请查看 install.log ——\n")
    clash_url = f"http://{server_ip}/clash.yaml"
    filename = f"clash_subscription_{server_ip}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(clash_url + "\n")
    print(f"Clash 订阅地址已写入 {filename}：\n{clash_url}\n")

    ssh.close()

if __name__ == "__main__":
    main()
