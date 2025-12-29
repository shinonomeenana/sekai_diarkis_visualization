from typing import List, Optional

# 1. 先导入 Scapy 的配置模块
from scapy.config import conf

# 2. 【关键步骤】在导入任何层（Layers）之前，强制关闭 IPv6
# 这样 scapy.layers.inet 就不会去加载 inet6，也就不会触发路由表读取崩溃
conf.ipv6_enabled = False

# 3. 现在可以安全导入其他模块了
from scapy.utils import PcapReader
from scapy.layers.inet import IP, UDP

def parse_udp_cap(file_path, udp_port: list = []) -> Optional[List[dict] | None]:
    print(f"[*] 开始解析文件: {file_path}")
    results = []
    
    try:
        with PcapReader(file_path) as pcap_reader:
            count = 0
            for packet in pcap_reader:
                # 只处理 UDP 包
                if not packet.haslayer(UDP):
                    continue
                
                # 提取 IP 层信息 (仅限 IPv4)
                src_ip = "Unknown"
                dst_ip = "Unknown"
                
                # 由于关闭了 IPv6，这里我们只处理 IP (IPv4)
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                else:
                    # 如果不是 IPv4 包，直接跳过
                    continue
                
                count += 1
                
                # 提取端口和载荷
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                payload = bytes(packet[UDP].payload)

                if len(payload) > 0 and (src_port in udp_port or dst_port in udp_port):
                    # print("-" * 50)
                    # print(f"Packet #{count}")
                    # print(f"Source: {src_ip}:{src_port} -> Dest: {dst_ip}:{dst_port}")
                    # print(f"Payload Length: {len(payload)} bytes")
                    # print(f"Data (Hex): {payload[:32].hex()}...")
                    results.append({
                        'seq': count,
                        'src_ip': src_ip,
                        'src_port': src_port,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                        'payload': payload,
                        'client': dst_port in udp_port
                    })
        return results

    except FileNotFoundError:
        print(f"[-] 错误: 找不到文件 {file_path}")
        return None
    except Exception as e:
        print(f"[-] 解析出错: {e}")
        return None

if __name__ == "__main__":
    cap_file = "traffic.pcap" 
    parse_udp_cap(cap_file, [7200])
