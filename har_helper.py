import json
import os
from typing import Tuple, Optional
from DiarkisUtils import Encryption

def export_diarkis_responses(har_file_path, output_file='diarkis_auth_data.json') -> Optional[Tuple[dict, list] | None]:
    """
    解析 HAR 文件，提取 URL 包含 'diarkis-auth' 的响应体，并保存为 JSON 文件。
    """
    
    # 1. 加载 HAR 文件
    if not os.path.exists(har_file_path):
        print(f"❌ 错误: 找不到文件 {har_file_path}")
        return None

    try:
        with open(har_file_path, 'r', encoding='utf-8') as f:
            har_data = json.load(f)
    except Exception as e:
        print(f"❌ 解析 HAR 文件失败: {e}")
        return None

    entries = har_data.get('log', {}).get('entries', [])
    extracted_data = []
    
    print(f"🔍 正在扫描 {len(entries)} 个请求...")

    udp_set = []

    # 2. 遍历并过滤
    for index, entry in enumerate(entries):
        request = entry.get('request', {})
        url = request.get('url', '')

        # 核心过滤条件
        if 'diarkis-auth' in url:
            response = entry.get('response', {})
            content = response.get('content', {})
            mime_type = content.get('mimeType', '')
            text_data = content.get('text')

            if not text_data:
                continue

            # 尝试处理 Base64 编码 (有些 HAR 文件会将二进制数据 base64 编码)
            if content.get('encoding') == 'base64':
                import base64
                try:
                    # 如果是文本内容的 base64，尝试解码
                    text_data = base64.b64decode(text_data).decode('utf-8')
                except:
                    pass # 如果解码失败或真的是二进制，保持原样

            # 尝试将响应体解析为 JSON 对象，以便在输出文件中格式化显示
            try:
                parsed_body = json.loads(text_data)
            except (json.JSONDecodeError, TypeError):
                # 如果不是 JSON，就保存原始字符串
                parsed_body = text_data

            auth_json = Encryption.DecryptApiResponse(base64.b64decode(parsed_body))
            udp_set.append(auth_json['udpPort'])
            # 收集数据
            extracted_data.append({
                'id': index + 1,
                'url': url,
                'status': response.get('status'),
                'mime_type': mime_type,
                'response_body': auth_json  # 这里存放的是清洗后的数据
            })
    udp_set = list(set(udp_set))
    # 3. 导出结果
    if extracted_data:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(extracted_data, f, indent=4, ensure_ascii=False)
            
            print(f"✅ 成功! 共找到 {len(extracted_data)} 条相关记录。")
            print(f"📂 结果已保存至: {output_file}")
        except Exception as e:
            print(f"❌ 写入文件失败: {e}")
    else:
        print("⚠️ 未找到包含 'diarkis-auth' 的请求。")
    return extracted_data, udp_set

# --- 使用说明 ---
# 请将下面的 'your_capture.har' 替换为你的实际文件名
# export_diarkis_responses('traffic.har')
