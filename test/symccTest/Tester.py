#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
一个通用程序执行速度测试工具。
该工具可以测量一个目标程序在指定时间内可以被执行多少次，
并计算出“每秒执行次数”。

新功能: 支持通过 --stdin-file 参数从文件向目标程序的标准输入提供内容。
"""

import subprocess
import time
import argparse
import sys
from typing import List, Optional

def run_target(command: List[str], stdin_content: Optional[bytes] = None):
    """
    运行一次目标程序，并捕获其输出。
    
    Args:
        command: 要执行的命令列表。
        stdin_content: 作为标准输入传递给程序的字节串内容。
    
    如果程序以非零状态码退出（即崩溃或出错），则会抛出异常。
    """
    subprocess.run(
        command,
        input=stdin_content, # 将内容传递给程序的标准输入
        capture_output=True, # 捕获stdout和stderr，不让它们显示在屏幕上
        check=True           # 如果返回码非零，则抛出 CalledProcessError 异常
    )

def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="测试目标程序的执行速度 (每秒执行次数)。",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
使用示例:
  # 1. 测试 'ls -l /tmp' 命令的速度 (无标准输入)，运行5秒
  ./speed_tester.py -d 5 /bin/ls -l /tmp
  
  # 2. 测试 'base64' 命令的速度，从 'input.txt' 文件读取标准输入
  #    相当于命令行中的: cat input.txt | base64
  ./speed_tester.py --stdin-file input.txt /usr/bin/base64

  # 3. 测试 'md5sum'，从文件读取标准输入，并运行15秒
  #    相当于命令行中的: md5sum < my_large_file.bin
  ./speed_tester.py -d 15 --stdin-file my_large_file.bin /usr/bin/md5sum

  # 4. 在Windows上测试 'findstr' 命令，从文件读取输入
  #    相当于: findstr "error" < log.txt
  python speed_tester.py --stdin-file log.txt C:\\Windows\\System32\\findstr.exe "error"
"""
    )
    
    parser.add_argument(
        '-d', '--duration',
        type=int,
        default=10,
        help="测试运行的总秒数 (默认: 10秒)"
    )
    
    parser.add_argument(
        '--stdin-file',
        type=str,
        default=None,
        help="指定一个文件，其内容将作为目标程序的标准输入 (stdin)。"
    )
    
    parser.add_argument(
        'target',
        help="要测试的目标程序的路径。"
    )
    
    parser.add_argument(
        'target_args',
        nargs=argparse.REMAINDER,
        help="传递给目标程序的参数。"
    )
    
    args = parser.parse_args()
    
    command_to_run = [args.target] + args.target_args
    stdin_data = None
    
    # 如果用户指定了标准输入文件，则读取它
    if args.stdin_file:
        try:
            with open(args.stdin_file, 'rb') as f:
                stdin_data = f.read()
            print(f"[*] 已加载标准输入文件: {args.stdin_file} ({len(stdin_data)} bytes)")
        except FileNotFoundError:
            print(f"[!] 错误: 找不到标准输入文件 '{args.stdin_file}'。")
            sys.exit(1)
        except IOError as e:
            print(f"[!] 错误: 读取标准输入文件 '{args.stdin_file}' 失败: {e}")
            sys.exit(1)

    print("\n--- 程序执行速度测试 ---")
    print(f"[*] 目标程序: {' '.join(command_to_run)}")
    if args.stdin_file:
        print(f"[*] 标准输入: 来自文件 '{args.stdin_file}'")
    print(f"[*] 测试时长: {args.duration} 秒")
    print("--------------------------")
    
    count = 0
    start_time = time.monotonic()
    
    try:
        # 主测试循环
        while True:
            current_time = time.monotonic()
            elapsed_time = current_time - start_time
            
            if elapsed_time >= args.duration:
                break
                
            print(f"\r[*] 运行中... 执行次数: {count}, 已用时间: {elapsed_time:.2f}s", end="")
            
            run_target(command_to_run, stdin_content=stdin_data)
            count += 1

    except FileNotFoundError:
        print(f"\n[!] 错误: 找不到目标程序 '{args.target}'。请检查路径是否正确。")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print("\n\n[!] 错误: 目标程序执行失败，已停止测试。")
        print(f"    - 命令: {' '.join(e.cmd)}")
        print(f"    - 返回码: {e.returncode}")
        stdout = e.stdout.decode('utf-8', errors='ignore')
        stderr = e.stderr.decode('utf-8', errors='ignore')
        if stdout:
            print(f"    - 标准输出:\n{stdout}")
        if stderr:
            print(f"    - 标准错误:\n{stderr}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] 发生未知错误: {e}")
        sys.exit(1)
        
    end_time = time.monotonic()
    total_time = end_time - start_time
    
    print("\n\n--- 测试结果 ---")
    print(f"[+] 总执行次数: {count}")
    print(f"[+] 总耗时: {total_time:.4f} 秒")
    
    if total_time > 0:
        speed = count / total_time
        print(f"[+] 执行速度: {speed:.2f} 次/秒")
    else:
        print("[+] 执行速度: N/A (耗时过短)")
    print("------------------")

if __name__ == "__main__":
    main()