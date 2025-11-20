#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bitwarden Authenticator CSV转JSON转换工具

支持多种UUID生成方式：
1. 随机UUID（最安全）
2. 固定UUID（基于otpauth数据）
3. 安全固定UUID（增强哈希方法）

使用方法：
python bitwarden_converter.py input.csv output.json [uuid_type]

uuid_type可选值：
- random: 随机UUID（默认）
- fixed: 固定UUID（基于UUID5）
- secure: 安全固定UUID（基于SHA256）
"""

import csv
import json
import uuid
import urllib.parse
import hashlib
import sys
import os
from typing import List, Dict, Any

class BitwardenConverter:
    """Bitwarden Authenticator CSV转JSON转换器"""
    
    def __init__(self, uuid_type: str = "random"):
        """
        初始化转换器
        
        参数:
            uuid_type: UUID生成类型 ("random", "fixed", "secure")
        """
        self.uuid_type = uuid_type
        self.salt = "bitwarden_authenticator_salt_2024"
        
    def generate_random_uuid(self) -> str:
        """生成随机UUID"""
        return str(uuid.uuid4()).upper()
    
    def generate_fixed_uuid_from_otpauth(self, otpauth_uri: str) -> str:
        """
        根据otpauth URI生成固定的UUID（基于UUID5）
        
        参数:
            otpauth_uri: otpauth格式的URI
            
        返回:
            固定的UUID字符串（大写）
        """
        # 使用UUID5命名空间DNS
        namespace = uuid.NAMESPACE_DNS
        
        # 解析URI获取参数
        parsed = urllib.parse.urlparse(otpauth_uri)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # 获取issuer和secret参数
        issuer = query_params.get('issuer', [''])[0]
        secret = query_params.get('secret', [''])[0]
        
        # 构建用于生成UUID的字符串
        uuid_string = f"{issuer}:{secret}"
        
        # 生成UUID5（基于SHA1哈希的确定性UUID）
        fixed_uuid = uuid.uuid5(namespace, uuid_string)
        
        return str(fixed_uuid).upper()
    
    def generate_secure_uuid_from_otpauth(self, otpauth_uri: str) -> str:
        """
        使用更安全的方法生成固定UUID（基于SHA256）
        
        参数:
            otpauth_uri: otpauth格式的URI
            
        返回:
            固定的UUID字符串（大写）
        """
        # 解析URI获取参数
        parsed = urllib.parse.urlparse(otpauth_uri)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # 获取参数
        issuer = query_params.get('issuer', [''])[0]
        secret = query_params.get('secret', [''])[0]
        
        # 构建更复杂的输入字符串，包含盐值
        uuid_input = f"{self.salt}:{issuer}:{secret}"
        
        # 使用SHA256哈希（比SHA1更安全）
        hash_obj = hashlib.sha256(uuid_input.encode('utf-8'))
        hash_bytes = hash_obj.digest()
        
        # 将bytes转换为可变的bytearray
        uuid_bytes = bytearray(hash_bytes[:16])
        
        # 设置版本（4）和变体（RFC 4122）
        uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40  # 版本4
        uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80  # 变体
        
        # 转换为UUID
        secure_uuid = uuid.UUID(bytes=bytes(uuid_bytes))
        
        return str(secure_uuid).upper()
    
    def generate_uuid(self, otpauth_uri: str) -> str:
        """
        根据配置的UUID类型生成UUID
        
        参数:
            otpauth_uri: otpauth格式的URI
            
        返回:
            UUID字符串（大写）
        """
        if self.uuid_type == "fixed":
            return self.generate_fixed_uuid_from_otpauth(otpauth_uri)
        elif self.uuid_type == "secure":
            return self.generate_secure_uuid_from_otpauth(otpauth_uri)
        else:  # random
            return self.generate_random_uuid()
    
    def build_otpauth_uri(self, name: str, secret: str, issuer: str) -> str:
        """
        构建otpauth URI
        
        参数:
            name: 账户名称
            secret: TOTP密钥
            issuer: 发行者
            
        返回:
            otpauth URI字符串
        """
        # 对name进行URL编码
        encoded_name = urllib.parse.quote(name)
        # 构建otpauth URI
        return f"otpauth://totp/{encoded_name}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    
    def read_csv_file(self, input_path: str) -> List[Dict[str, str]]:
        """
        读取CSV文件
        
        参数:
            input_path: 输入CSV文件路径
            
        返回:
            CSV数据列表
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"输入文件不存在: {input_path}")
        
        with open(input_path, 'r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            return list(csv_reader)
    
    def convert_row_to_item(self, row: Dict[str, str]) -> Dict[str, Any]:
        """
        将CSV行转换为Bitwarden项目
        
        参数:
            row: CSV行数据
            
        返回:
            Bitwarden项目字典
        """
        # 获取CSV中的字段
        name = row.get('name', '')
        secret = row.get('secret', '')
        issuer = row.get('issuer', '')
        url = row.get('url', '')
        
        # 如果URL为空，则构建otpauth URI
        if not url and secret:
            url = self.build_otpauth_uri(name, secret, issuer)
        
        # 生成UUID
        item_uuid = self.generate_uuid(url)
        
        # 创建Bitwarden项目
        item = {
            "favorite": False,
            "id": item_uuid,
            "login": {
                "totp": url,
                "username": name
            },
            "name": issuer if issuer else name,
            "type": 1  # 1表示登录类型
        }
        
        return item
    
    def convert_csv_to_json(self, input_path: str, output_path: str) -> None:
        """
        将CSV文件转换为Bitwarden Authenticator JSON格式
        
        参数:
            input_path: 输入CSV文件路径
            output_path: 输出JSON文件路径
        """
        # 读取CSV文件
        csv_data = self.read_csv_file(input_path)
        
        # 准备JSON数据结构
        bitwarden_data = {
            "encrypted": False,
            "items": []
        }
        
        # 处理每一行CSV数据
        for row in csv_data:
            try:
                item = self.convert_row_to_item(row)
                bitwarden_data["items"].append(item)
            except Exception as e:
                print(f"警告：跳过无效行 {row}，错误：{e}")
                continue
        
        # 写入JSON文件
        with open(output_path, 'w', encoding='utf-8') as json_file:
            json.dump(bitwarden_data, json_file, indent=2, ensure_ascii=False)
        
        print(f"✅ 转换完成！")
        print(f"📁 输入文件: {input_path}")
        print(f"📁 输出文件: {output_path}")
        print(f"🔢 UUID类型: {self.uuid_type}")
        print(f"📊 成功转换项目数: {len(bitwarden_data['items'])}")
    
    def create_sample_csv(self, file_path: str) -> None:
        """
        创建示例CSV文件
        
        参数:
            file_path: CSV文件路径
        """
        sample_data = [
            ['name', 'secret', 'issuer', 'type', 'counter', 'url'],
            ['dean@outlook.com', 'TESTTESTTESTTSET', 'Microsoft', 'totp', '', ''],
            ['alice@gmail.com', 'JBSWY3DPEHPK3PXP', 'Google', 'totp', '', ''],
            ['bob@company.com', 'MFRGGZDFMZTWQ2LK', 'GitHub', 'totp', '', '']
        ]
        
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerows(sample_data)
        
        print(f"📝 已创建示例文件: {file_path}")

def demo_uuid_generation():
    """演示不同UUID生成方法"""
    print("=== UUID生成方法演示 ===\n")
    
    # 示例otpauth URI
    sample_uri = "otpauth://totp/Amazon:alice@bitwarden.com?secret=IIO5SCP3766LMSAB5HJCQPNDCCNAZ532&issuer=Amazon&algorithm=SHA1&digits=6&period=30"
    
    # 创建不同类型的转换器
    converters = {
        "random": BitwardenConverter("random"),
        "fixed": BitwardenConverter("fixed"),
        "secure": BitwardenConverter("secure")
    }
    
    print(f"示例URI: {sample_uri}")
    print("-" * 80)
    
    for uuid_type, converter in converters.items():
        uuid1 = converter.generate_uuid(sample_uri)
        uuid2 = converter.generate_uuid(sample_uri)
        
        print(f"{uuid_type.upper():8} UUID1: {uuid1}")
        print(f"{uuid_type.upper():8} UUID2: {uuid2}")
        print(f"{uuid_type.upper():8} 一致性: {'✅' if uuid1 == uuid2 else '❌'}")
        print()

def print_usage():
    """打印使用说明"""
    print("""
Bitwarden Authenticator CSV转JSON转换工具

使用方法:
    python bitwarden_converter.py input.csv output.json [uuid_type]

参数说明:
    input.csv   : 输入的CSV文件路径
    output.json : 输出的JSON文件路径
    uuid_type   : UUID生成类型 (可选)
                  - random: 随机UUID（默认，最安全）
                  - fixed: 固定UUID（基于UUID5）
                  - secure: 安全固定UUID（基于SHA256）

CSV格式要求:
    name,secret,issuer,type,counter,url
    dean@outlook.com,TESTTESTTESTTSET,Microsoft,totp,,

示例:
    # 使用随机UUID（推荐）
    python bitwarden_converter.py my_accounts.csv bitwarden.json random
    
    # 使用固定UUID
    python bitwarden_converter.py my_accounts.csv bitwarden.json fixed
    
    # 使用安全固定UUID
    python bitwarden_converter.py my_accounts.csv bitwarden.json secure
""")

def main():
    """主函数"""
    # 检查命令行参数
    if len(sys.argv) < 2 or sys.argv[1] in ['-h', '--help', 'help']:
        print_usage()
        return
    
    # 解析参数
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "bitwarden_authenticator.json"
    uuid_type = sys.argv[3] if len(sys.argv) > 3 else "random"
    
    # 验证UUID类型
    if uuid_type not in ["random", "fixed", "secure"]:
        print(f"❌ 错误：不支持的UUID类型 '{uuid_type}'")
        print("支持的类型: random, fixed, secure")
        return
    
    try:
        # 创建转换器
        converter = BitwardenConverter(uuid_type)
        
        # 如果输入文件不存在，创建示例文件
        if not os.path.exists(input_file):
            print(f"⚠️  输入文件不存在: {input_file}")
            converter.create_sample_csv(input_file)
            print("请编辑示例文件后重新运行程序")
            return
        
        # 执行转换
        converter.convert_csv_to_json(input_file, output_file)
        
    except Exception as e:
        print(f"❌ 转换失败: {e}")
        return

if __name__ == "__main__":
    # 运行演示
    if len(sys.argv) == 1:
        demo_uuid_generation()
        print("\n" + "="*80)
        print_usage()
    else:
        main()
