"""vault.py — 程序入口

用法：
    python vault.py                          # 启动
    python vault.py --vault D:/data/vault.dat  # 指定库文件路径
    python vault.py --restore-key keybackup.vkb --mount E:\\   # 独立恢复密钥
"""
import argparse
import os
import sys

from cli import App, restore_key_cli


def main():
    parser = argparse.ArgumentParser(description="U盘钥匙密码保险箱（CLI）")
    parser.add_argument("--vault", default=None, help="库文件路径（默认脚本同目录 vault.dat）")
    parser.add_argument("--restore-key", metavar="BACKUP_FILE", help="从密钥备份包恢复 keyfile 到U盘后退出")
    parser.add_argument("--mount", help="配合 --restore-key 指定目标U盘挂载点")
    args = parser.parse_args()

    if args.restore_key:
        restore_key_cli(args.restore_key, args.mount)
        return

    vault_path = args.vault or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "vault.dat"
    )
    app = App(vault_path)
    try:
        app.run()
    except KeyboardInterrupt:
        app.lock("中断", force=True)
        print("\n已退出。")


if __name__ == "__main__":
    main()