#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
攻击统计脚本

用于统计防火墙和探针目录下的攻击次数，生成统计报告
"""

import argparse
import csv
import os
import re
from collections import defaultdict
from typing import Dict, List, Tuple, Set


def format_number(number: int) -> str:
    """
    格式化数字，超过1万显示为x.xxxxW格式

    Args:
        number (int): 要格式化的数字

    Returns:
        str: 格式化后的字符串
    """
    if number >= 10000:
        return f"{number / 10000:.4f}W"
    else:
        return str(number)


def read_csv_files(directory: str) -> List[Dict]:
    """
    读取目录下所有CSV文件的数据

    Args:
        directory (str): 目录路径

    Returns:
        List[Dict]: 所有CSV文件的数据列表
    """
    all_data = []

    if not os.path.exists(directory):
        print(f"警告: 目录 {directory} 不存在")
        return all_data

    # 检查是目录还是文件
    if os.path.isfile(directory) and directory.lower().endswith('.csv'):
        # 单个CSV文件
        return read_csv_file(directory)

    csv_files = [f for f in os.listdir(directory) if f.lower().endswith('.csv')]

    if not csv_files:
        print(f"警告: 目录 {directory} 中没有CSV文件")
        return all_data

    for csv_file in csv_files:
        file_path = os.path.join(directory, csv_file)
        data = read_csv_file(file_path)
        all_data.extend(data)

    return all_data


def read_csv_file(file_path: str) -> List[Dict]:
    """
    读取单个CSV文件的数据

    Args:
        file_path (str): CSV文件路径

    Returns:
        List[Dict]: CSV文件的数据列表
    """
    data = []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # 尝试检测CSV分隔符
            sample = f.read(1024)
            f.seek(0)

            # 检测分隔符
            delimiter = ','
            if sample.count('\t') > sample.count(','):
                delimiter = '\t'
            elif sample.count(';') > sample.count(','):
                delimiter = ';'

            reader = csv.DictReader(f, delimiter=delimiter)
            for row in reader:
                if row:  # 跳过空行
                    data.append(row)

        print(f"✓ 成功读取文件: {os.path.basename(file_path)} ({len(data)} 条记录)")

    except Exception as e:
        print(f"✗ 读取文件 {file_path} 失败: {str(e)}")

    return data


def extract_ip_from_attack_data(data: Dict, ip_columns: List[str]) -> str:
    """
    从攻击数据中提取IP地址

    Args:
        data (Dict): 攻击数据行
        ip_columns (List[str]): 可能包含IP的列名列表

    Returns:
        str: 提取到的IP地址，如果没找到返回空字符串
    """
    for col in ip_columns:
        if col in data and data[col]:
            ip = data[col].strip()
            # 简单的IP地址验证
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                return ip

    # 如果没有找到标准IP列，尝试从所有字段中找IP
    for value in data.values():
        if value and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(value).strip()):
            return str(value).strip()

    return ""


def count_attacks(firewall_data: List[Dict], probe_data: List[Dict]) -> Tuple[int, int, Dict[str, int], Set[str]]:
    """
    统计攻击次数

    Args:
        firewall_data (List[Dict]): 防火墙数据
        probe_data (List[Dict]): 探针数据

    Returns:
        Tuple[int, int, Dict[str, int], Set[str]]:
            (防火墙攻击次数, 探针攻击次数, 合并IP攻击统计, 探针独立IP集合)
    """

    # 统计防火墙攻击次数（每条记录算1次攻击）
    firewall_attacks = len(firewall_data)

    # 统计探针攻击次数（使用命中数字段）
    probe_attacks = 0
    for row in probe_data:
        try:
            # 探针数据使用"命中数"字段作为实际攻击次数
            if '命中数' in row and row['命中数']:
                hit_count = int(str(row['命中数']).strip())
                probe_attacks += hit_count
            elif 'hit_count' in row and row['hit_count']:
                hit_count = int(str(row['hit_count']).strip())
                probe_attacks += hit_count
            else:
                # 如果没有命中数字段，算作1次攻击
                probe_attacks += 1
        except (ValueError, TypeError):
            # 转换失败时算作1次攻击
            probe_attacks += 1

    # 可能包含IP地址的列名（根据真实文件格式优化）
    ip_columns = [
        '源IP', '源IP地址', '攻击源IP', '源地址',
        '目的IP', '目标IP', '目的IP地址', '目标地址',
        'src_ip', 'source_ip', 'sip', '攻击IP',
        'dst_ip', 'dest_ip', 'dip',
        'ip', 'client_ip', 'server_ip', 'host_ip',
        '攻击者', '受害者'  # 探针文件中的IP字段
    ]

    # 统计探针独立IP
    probe_ips = set()
    for row in probe_data:
        ip = extract_ip_from_attack_data(row, ip_columns)
        if ip:
            probe_ips.add(ip)

    # 合并统计IP攻击次数
    ip_attack_count = defaultdict(int)

    # 统计防火墙IP攻击次数（每条记录算1次）
    for row in firewall_data:
        ip = extract_ip_from_attack_data(row, ip_columns)
        if ip:
            ip_attack_count[ip] += 1

    # 统计探针IP攻击次数（使用命中数）
    for row in probe_data:
        ip = extract_ip_from_attack_data(row, ip_columns)
        if ip:
            try:
                # 使用命中数字段作为攻击次数
                if '命中数' in row and row['命中数']:
                    hit_count = int(str(row['命中数']).strip())
                    ip_attack_count[ip] += hit_count
                elif 'hit_count' in row and row['hit_count']:
                    hit_count = int(str(row['hit_count']).strip())
                    ip_attack_count[ip] += hit_count
                else:
                    # 如果没有命中数字段，算作1次攻击
                    ip_attack_count[ip] += 1
            except (ValueError, TypeError):
                # 转换失败时算作1次攻击
                ip_attack_count[ip] += 1

    return firewall_attacks, probe_attacks, dict(ip_attack_count), probe_ips


def generate_report(firewall_attacks: int, probe_attacks: int, probe_ips: Set[str],
                    ip_attack_count: Dict[str, int], template: str) -> str:
    """
    生成统计报告

    Args:
        firewall_attacks (int): 防火墙攻击次数
        probe_attacks (int): 探针攻击次数
        probe_ips (Set[str]): 探针独立IP集合
        ip_attack_count (Dict[str, int]): IP攻击次数统计
        template (str): 报告模板

    Returns:
        str: 生成的报告
    """
    # 统计超过50次攻击的IP
    high_risk_ips = {ip: count for ip, count in ip_attack_count.items() if count > 50}
    high_risk_count = len(high_risk_ips)

    # 格式化数字
    firewall_attacks_str = format_number(firewall_attacks)
    probe_attacks_str = format_number(probe_attacks)
    probe_ip_count = len(probe_ips)

    # 替换模板占位符（使用简化的占位符名称）
    report = template.replace("{防火墙攻击次数}", firewall_attacks_str)
    report = report.replace("{探针攻击次数}", probe_attacks_str)
    report = report.replace("{探针攻击ip数}", str(probe_ip_count))
    report = report.replace("{高风险ip数}", str(high_risk_count))

    # 兼容旧的占位符名称
    report = report.replace("{防火墙攻击次数（超过1万就记成x.xxxxW）}", firewall_attacks_str)
    report = report.replace("{探针攻击次数（超过1万就记成x.xxxxW）}", probe_attacks_str)
    report = report.replace("{和在一起，超过50次的ip数量}", str(high_risk_count))

    return report


def save_template_example():
    """保存模板示例文件"""
    # 使用简化占位符的新模板
    template_content = """山南防火墙共监测到{防火墙攻击次数}次攻击，山南探针共监测{探针攻击ip数}个IP的{探针攻击次数}次攻击，分析了{探针攻击次数}条告警日志，分析后进行了{高风险ip数}次封堵，未发现攻击成功事件，并根据威胁情报封禁了0个IP。"""

    with open('report_template.txt', 'w', encoding='utf-8') as f:
        f.write(template_content)

    print("✓ 已创建报告模板示例文件: report_template.txt")
    print("✓ 新模板使用简化的占位符名称：")
    print("   - {防火墙攻击次数}")
    print("   - {探针攻击次数}")
    print("   - {探针攻击ip数}")
    print("   - {高风险ip数}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='攻击统计工具')
    parser.add_argument('--firewall-dir', help='防火墙CSV文件目录')
    parser.add_argument('--probe-dir', help='探针CSV文件目录')
    parser.add_argument('--template', help='自定义报告模板文件路径')
    parser.add_argument('--create-template', action='store_true', help='创建模板示例文件')
    parser.add_argument('--output', help='输出报告文件路径（默认输出到控制台）')

    args = parser.parse_args()

    # 创建模板示例
    if args.create_template:
        save_template_example()
        return

    # 检查必需参数
    if not args.firewall_dir or not args.probe_dir:
        print("错误: 需要指定 --firewall-dir 和 --probe-dir 参数")
        parser.print_help()
        return

    # 读取模板
    if args.template and os.path.exists(args.template):
        with open(args.template, 'r', encoding='utf-8') as f:
            template = f.read().strip()
        print(f"✓ 已加载自定义模板: {args.template}")
    else:
        # 使用默认模板（简化占位符）
        template = """山南防火墙共监测到{防火墙攻击次数}次攻击，山南探针共监测{探针攻击ip数}个IP的{探针攻击次数}次攻击，分析了{探针攻击次数}条告警日志，分析后进行了{高风险ip数}次封堵，未发现攻击成功事件，并根据威胁情报封禁了0个IP。"""
        print("✓ 使用默认报告模板（简化的占位符）")

    print("=" * 60)
    print("攻击统计工具")
    print("=" * 60)

    # 读取数据
    print(f"正在读取防火墙目录: {args.firewall_dir}")
    firewall_data = read_csv_files(args.firewall_dir)

    print(f"正在读取探针目录: {args.probe_dir}")
    probe_data = read_csv_files(args.probe_dir)

    print("-" * 60)

    # 统计攻击
    print("正在统计数据...")
    firewall_attacks, probe_attacks, ip_attack_count, probe_ips = count_attacks(firewall_data, probe_data)

    # 输出基础统计
    print(f"防火墙攻击次数: {firewall_attacks} ({format_number(firewall_attacks)})")
    print(f"探针攻击次数: {probe_attacks} ({format_number(probe_attacks)})")
    print(f"探针独立IP数: {len(probe_ips)}")

    # 统计高风险IP
    high_risk_ips = {ip: count for ip, count in ip_attack_count.items() if count > 50}
    high_risk_count = len(high_risk_ips)

    print(f"超过50次攻击的IP数量: {high_risk_count}")

    if high_risk_ips:
        print("\n超过50次攻击的IP列表:")
        for ip, count in sorted(high_risk_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"  {ip}: {count} 次")

    print("-" * 60)

    # 生成报告
    report = generate_report(firewall_attacks, probe_attacks, probe_ips, ip_attack_count, template)

    print("统计报告:")
    print(report)

    # 保存报告
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\n✓ 报告已保存到: {args.output}")

    print("\n✓ 统计完成！")


if __name__ == '__main__':
    main()
