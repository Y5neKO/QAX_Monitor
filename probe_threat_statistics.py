#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
探针威胁分类统计脚本

用于统计指定目录内所有CSV文件中的威胁分类，按数量排序
"""

import argparse
import csv
import os
from collections import Counter
from typing import Dict, List


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


def extract_threat_categories(data: List[Dict]) -> Counter:
    """
    从数据中提取威胁分类并统计

    Args:
        data (List[Dict]): CSV数据列表

    Returns:
        Counter: 威胁分类统计
    """
    threat_categories = Counter()

    # 可能包含威胁分类的列名
    category_columns = [
        '威胁分类', '威胁类别', '威胁类型', '分类', '类别',
        'threat_category', 'threat_type', 'threat_classification',
        'category', 'type', 'classification',
        '攻击类型', 'attack_type', 'attack_category'
    ]

    for row in data:
        found_category = False

        # 按优先级查找威胁分类字段
        for col in category_columns:
            if col in row and row[col]:
                category = str(row[col]).strip()
                if category and category != '' and category.lower() != 'null':
                    threat_categories[category] += 1
                    found_category = True
                    break

        # 如果没有找到专门的分类字段，尝试从威胁事件字段中提取
        if not found_category:
            for value in data.values():
                if value and len(str(value)) < 50:  # 避免长文本
                    text = str(value).strip()
                    # 常见威胁分类关键词
                    threat_keywords = [
                        '漏洞扫描', '信息泄露', 'DDoS攻击', 'Web攻击', '恶意软件',
                        '网络攻击', '可疑行为', '安全事件', '病毒', '木马',
                        '钓鱼', '垃圾邮件', '入侵检测', '异常访问', '数据窃取'
                    ]
                    for keyword in threat_keywords:
                        if keyword in text:
                            threat_categories[text] += 1
                            found_category = True
                            break
                if found_category:
                    break

    return threat_categories


def generate_category_report(threat_categories: Counter, total_records: int) -> str:
    """
    生成威胁分类统计报告

    Args:
        threat_categories (Counter): 威胁分类统计
        total_records (int): 总记录数

    Returns:
        str: 生成的报告
    """
    if not threat_categories:
        return "未发现任何威胁分类数据。"

    report_lines = ["威胁分类统计报告", "=" * 50, f"总记录数: {format_number(total_records)}",
                    f"威胁分类数量: {len(threat_categories)}", ""]

    # 按数量排序，从多到少
    sorted_categories = threat_categories.most_common()

    report_lines.append("威胁分类排名 (按数量排序):")
    report_lines.append("-" * 50)

    for i, (category, count) in enumerate(sorted_categories, 1):
        percentage = (count / total_records) * 100 if total_records > 0 else 0
        report_lines.append(f"{i:2d}. {category:<20} {format_number(count):>8} ({percentage:5.1f}%)")

    report_lines.append("")
    report_lines.append("详细统计:")
    report_lines.append("-" * 30)

    # 统计摘要
    top_category = sorted_categories[0]
    report_lines.append(f"最常见威胁: {top_category[0]} ({format_number(top_category[1])}次)")

    # 统计前5名的占比
    top5_count = sum(count for _, count in sorted_categories[:5])
    top5_percentage = (top5_count / total_records) * 100 if total_records > 0 else 0
    report_lines.append(f"前5名占比: {top5_percentage:.1f}%")

    return "\n".join(report_lines)


def save_report_to_file(report: str, output_path: str):
    """
    保存报告到文件

    Args:
        report (str): 报告内容
        output_path (str): 输出文件路径
    """
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"✓ 报告已保存到: {output_path}")
    except Exception as e:
        print(f"✗ 保存报告失败: {str(e)}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='探针威胁分类统计工具')
    parser.add_argument('directory', help='探针CSV文件目录路径')
    parser.add_argument('--output', '-o', help='输出报告文件路径（默认输出到控制台）')
    parser.add_argument('--min-count', type=int, default=1,
                        help='最小显示数量阈值，只显示超过此数量的分类（默认：1）')

    args = parser.parse_args()

    if not args.directory:
        print("错误: 需要指定探针CSV文件目录路径")
        parser.print_help()
        return

    print("=" * 60)
    print("探针威胁分类统计工具")
    print("=" * 60)

    # 读取数据
    print(f"正在读取探针目录: {args.directory}")
    probe_data = read_csv_files(args.directory)

    if not probe_data:
        print("✗ 没有找到有效的数据")
        return

    print(f"✓ 总共读取了 {len(probe_data)} 条记录")
    print("-" * 60)

    # 统计威胁分类
    print("正在统计威胁分类...")
    threat_categories = extract_threat_categories(probe_data)

    # 过滤低频分类
    if args.min_count > 1:
        threat_categories = Counter({
            category: count for category, count in threat_categories.items()
            if count >= args.min_count
        })

    if not threat_categories:
        print("✗ 没有找到符合条件的威胁分类数据")
        return

    # 生成报告
    report = generate_category_report(threat_categories, len(probe_data))

    # 输出报告
    print("\n" + report)

    # 保存报告
    if args.output:
        save_report_to_file(report, args.output)

    print("\n✓ 统计完成！")


if __name__ == '__main__':
    main()
