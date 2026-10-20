"""vault_gui.py — 图形界面入口

用法：
    python vault_gui.py                    # 默认使用同目录的 vault.dat
    python vault_gui.py D:/path/vault.dat  # 指定库文件路径
"""
import os
import sys
import tkinter as tk

from gui import VaultApp


def main():
    # 默认库文件放在脚本同目录，与 CLI 版保持一致
    vault_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "vault.dat"
    )
    if len(sys.argv) > 1:
        vault_path = sys.argv[1]

    root = tk.Tk()
    app = VaultApp(root, vault_path)
    # 点窗口右上角 X 时走 on_close（确保先锁定再销毁）
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()