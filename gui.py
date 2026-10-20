"""gui.py — Tkinter 图形界面

设计目标：
- 简约：只用 ttk 控件，无图片资源
- 轻量：纯标准库 Tkinter，运行内存 < 100MB
- 安全：与 CLI 版共用同一套密钥派生与存储逻辑（crypto_layer / storage 不动）

窗口结构：
    Root
    ├── 菜单栏（文件 / 安全 / 回收站/ 帮助）
    ├── container
    │   ├── lock_frame（未解锁时显示）
    │   └── main_frame（解锁后显示：工具栏 + Treeview 列表 + 底部按钮）
    └── 状态栏
"""
from __future__ import annotations

import hmac
import os
import secrets
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

try:
    import pyperclip
except ImportError:
    pyperclip = None

from crypto_layer import (
    KEYFILE_MAGIC,
    VaultError,
    WrongKeyfile,
    WrongPassword,
    b64d,
    check_final,
    check_k1,
    derive_final_key,
    derive_k1,
    make_key_backup,
    make_keyfile_file,
    open_key_backup,
    parse_keyfile_file,
)
from storage import VaultFile

IDLE_TIMEOUT = 600       # 空闲 10 分钟自动锁定
CLIPBOARD_CLEAR = 30     # 复制后 30 秒清空剪贴板


# ---------- 通用工具 ----------

def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def generate_password(length: int = 20) -> str:
    """生成随机密码，排除易混淆字符。"""
    lower = "abcdefghijkmnpqrstuvwxyz"
    upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    digits = "23456789"
    symbols = "!@#$%^&*-_=+?"
    alphabet = lower + upper + digits + symbols
    pw = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    pw += [secrets.choice(alphabet) for _ in range(max(0, length - 4))]
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)


def find_keyfile():
    """在所有盘符根目录下找 .vault_key。"""
    try:
        import psutil
    except ImportError:
        return None
    for p in psutil.disk_partitions(all=False):
        try:
            path = os.path.join(p.mountpoint, ".vault_key")
            if os.path.isfile(path):
                return path
        except Exception:
            continue
    return None


def read_keyfile(path: str) -> bytes:
    with open(path, "rb") as f:
        return parse_keyfile_file(f.read())


def copy_clipboard(text: str) -> bool:
    """复制到剪贴板，后台线程 N 秒后若未变化则清空。"""
    if pyperclip is None or not text:
        return False
    try:
        pyperclip.copy(text)
    except Exception:
        return False

    def clear():
        time.sleep(CLIPBOARD_CLEAR)
        try:
            if pyperclip.paste() == text:
                pyperclip.copy("")
        except Exception:
            pass

    threading.Thread(target=clear, daemon=True).start()
    return True


# ---------- 条目编辑对话框 ----------

class EntryDialog(tk.Toplevel):
    """新增 / 编辑条目的模态对话框。

    结果放在 self.result 里：
    - 用户点保存 -> dict，包含 title/username/password/url/tags/notes
    - 用户取消或关闭 -> None
    """

    def __init__(self, parent, title, entry=None):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)

        self.result = None
        self.entry = entry or {
            "title": "", "username": "", "password": "",
            "url": "", "tags": [], "notes": "",
        }

        self._build()
        self._center(parent)
        # 阻塞直到对话框关闭
        self.wait_window(self)

    def _build(self):
        frm = ttk.Frame(self, padding=15)
        frm.pack(fill="both", expand=True)

        # 标题
        ttk.Label(frm, text="标题:").grid(row=0, column=0, sticky="e", pady=3)
        self.title_var = tk.StringVar(value=self.entry["title"])
        ttk.Entry(frm, textvariable=self.title_var, width=35).grid(
            row=0, column=1, columnspan=2, sticky="we", pady=3)

        # 账号
        ttk.Label(frm, text="账号:").grid(row=1, column=0, sticky="e", pady=3)
        self.user_var = tk.StringVar(value=self.entry["username"])
        ttk.Entry(frm, textvariable=self.user_var, width=35).grid(
            row=1, column=1, columnspan=2, sticky="we", pady=3)

        # 密码 + 生成按钮
        ttk.Label(frm, text="密码:").grid(row=2, column=0, sticky="e", pady=3)
        self.pw_var = tk.StringVar(value=self.entry["password"])
        self.pw_entry = ttk.Entry(frm, textvariable=self.pw_var, width=25, show="*")
        self.pw_entry.grid(row=2, column=1, sticky="we", pady=3)
        ttk.Button(frm, text="生成", width=6, command=self._gen).grid(
            row=2, column=2, padx=(5, 0), pady=3)

        # 显示/隐藏密码
        self.show_pw = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="显示密码", variable=self.show_pw,
                        command=self._toggle_pw).grid(row=3, column=1, sticky="w")

        # 网址
        ttk.Label(frm, text="网址:").grid(row=4, column=0, sticky="e", pady=3)
        self.url_var = tk.StringVar(value=self.entry["url"])
        ttk.Entry(frm, textvariable=self.url_var, width=35).grid(
            row=4, column=1, columnspan=2, sticky="we", pady=3)

        # 标签
        ttk.Label(frm, text="标签:").grid(row=5, column=0, sticky="e", pady=3)
        self.tags_var = tk.StringVar(value=", ".join(self.entry["tags"]))
        ttk.Entry(frm, textvariable=self.tags_var, width=35).grid(
            row=5, column=1, columnspan=2, sticky="we", pady=3)

        # 备注（多行）
        ttk.Label(frm, text="备注:").grid(row=6, column=0, sticky="ne", pady=3)
        self.notes_text = tk.Text(frm, width=35, height=4, wrap="word")
        self.notes_text.grid(row=6, column=1, columnspan=2, sticky="we", pady=3)
        self.notes_text.insert("1.0", self.entry["notes"])

        # 按钮
        btns = ttk.Frame(frm)
        btns.grid(row=7, column=0, columnspan=3, pady=(10, 0), sticky="e")
        ttk.Button(btns, text="保存", command=self._save).pack(side="right", padx=(5, 0))
        ttk.Button(btns, text="取消", command=self.destroy).pack(side="right")

    def _gen(self):
        self.pw_var.set(generate_password(20))
        self.show_pw.set(True)
        self._toggle_pw()

    def _toggle_pw(self):
        self.pw_entry.config(show="" if self.show_pw.get() else "*")

    def _save(self):
        title = self.title_var.get().strip()
        if not title:
            messagebox.showwarning("提示", "标题不能为空", parent=self)
            return
        self.result = {
            "title": title,
            "username": self.user_var.get().strip(),
            "password": self.pw_var.get(),
            "url": self.url_var.get().strip(),
            "tags": [t.strip() for t in self.tags_var.get().split(",") if t.strip()],
            "notes": self.notes_text.get("1.0", "end").strip(),
        }
        self.destroy()

    def _center(self, parent):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        x = px + (pw - w) // 2
        y = py + (ph - h) // 2
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")


# ---------- 主应用 ----------

class VaultApp:
    def __init__(self, root: tk.Tk, vault_path: str):
        self.root = root
        self.vault_path = vault_path
        self.vault = VaultFile(vault_path)

        # 运行时状态（与 CLI 版对应）
        self.locked = True
        self.k1 = None
        self.salt = None
        self.params = None
        self.final_key = None
        self.header = None
        self.data = None
        self.keyfile_path = None
        self.keyfile_bytes = None
        self.last_activity = time.time()
        self.show_trash = False

        self._build_ui()
        self._start_monitors()
        self._show_lock_frame()
        # 延迟 200 毫秒检查初始状态（等窗口渲染完再弹窗）
        self.root.after(200, self._check_initial_state)

    # ---------- 界面构建 ----------

    def _build_ui(self):
        self.root.title("密码保险箱")
        self.root.minsize(720, 480)
        self.root.geometry("720x480")

        # ttk 主题：clam 跨平台一致，看起来更现代
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        # 行高稍大一点，列表更好看
        style.configure("Treeview", rowheight=24)

        self._build_menu()

        self.container = ttk.Frame(self.root)
        self.container.pack(fill="both", expand=True)

        self.lock_frame = self._build_lock_frame()
        self.main_frame = self._build_main_frame()

        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(self.root, textvariable=self.status_var, anchor="w",
                  relief="sunken", padding=(8, 3)).pack(side="bottom", fill="x")

        # 全局事件 -> 刷新活动时间
        self.root.bind_all("<Key>", self._record_activity)
        self.root.bind_all("<Button>", self._record_activity)

    def _build_menu(self):
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="新建保险库…", command=self.do_new_vault)  # ← 新增这行
        file_menu.add_command(label="备份库文件…", command=self.do_backup)
        file_menu.add_separator()
        file_menu.add_command(label="导出 CSV…", command=lambda: self.do_export("csv"))
        file_menu.add_command(label="导出 JSON…", command=lambda: self.do_export("json"))
        file_menu.add_command(label="导入 CSV…", command=self.do_import)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.on_close)
        menubar.add_cascade(label="文件", menu=file_menu)

        sec_menu = tk.Menu(menubar, tearoff=0)
        sec_menu.add_command(label="锁定", command=lambda: self.lock("手动锁定"))
        sec_menu.add_separator()
        sec_menu.add_command(label="修改主密码…", command=self.do_change_password)
        sec_menu.add_command(label="更换U盘密钥…", command=self.do_new_keyfile)
        sec_menu.add_separator()
        sec_menu.add_command(label="导出密钥备份包…", command=self.do_key_backup)
        sec_menu.add_command(label="从备份包恢复密钥…", command=self.do_restore_key)
        sec_menu.add_separator()  # ← 新增
        sec_menu.add_command(label="销毁保险库 (删除库和密钥)…", command=self.do_destroy_vault)  # ← 新增
        menubar.add_cascade(label="安全", menu=sec_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="使用说明", command=self.show_help)
        menubar.add_cascade(label="帮助", menu=help_menu)

        self.root.config(menu=menubar)

    def _build_lock_frame(self):
        """解锁界面：居中显示主密码输入。"""
        frame = ttk.Frame(self.container)
        box = ttk.Frame(frame)
        box.place(relx=0.5, rely=0.4, anchor="center")

        ttk.Label(box, text="密码保险箱", font=("", 18, "bold")).pack(pady=(0, 20))

        self.lock_hint = ttk.Label(box, text="", foreground="#666")
        self.lock_hint.pack(pady=(0, 10))

        pw_row = ttk.Frame(box)
        pw_row.pack(pady=5)
        ttk.Label(pw_row, text="主密码:").pack(side="left", padx=(0, 5))
        self.lock_pw_var = tk.StringVar()
        self.lock_pw_entry = ttk.Entry(pw_row, textvariable=self.lock_pw_var,
                                       show="*", width=25)
        self.lock_pw_entry.pack(side="left")
        self.lock_pw_entry.bind("<Return>", lambda e: self._on_unlock())

        self.lock_show_pw = tk.BooleanVar(value=False)
        ttk.Checkbutton(box, text="显示密码", variable=self.lock_show_pw,
                        command=self._toggle_lock_pw).pack(pady=(0, 10))

        self.unlock_btn = ttk.Button(box, text="解 锁", width=15, command=self._on_unlock)
        self.unlock_btn.pack(pady=5)

        self.lock_msg = ttk.Label(box, text="", foreground="#c00")
        self.lock_msg.pack(pady=(10, 0))

        return frame

    def _build_main_frame(self):
        """主界面：工具栏 + 列表 + 底部操作按钮。"""
        frame = ttk.Frame(self.container)

        # 工具栏
        toolbar = ttk.Frame(frame, padding=(8, 6))
        toolbar.pack(fill="x")

        ttk.Label(toolbar, text="搜索:").pack(side="left", padx=(0, 4))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self.refresh_list())
        ttk.Entry(toolbar, textvariable=self.search_var, width=30).pack(side="left", padx=(0, 8))

        # 新增按钮要保存引用，因为进回收站时它需要被禁用
        self.btn_add = ttk.Button(toolbar, text="新增", command=self.do_add)
        self.btn_add.pack(side="left", padx=2)
        ttk.Button(toolbar, text="刷新", command=self.refresh_list).pack(side="left", padx=2)

        ttk.Button(toolbar, text="锁定", command=lambda: self.lock("手动锁定")).pack(side="right", padx=2)

        # 视图切换按钮：文字随状态变化，始终可见
        self.btn_view_switch = ttk.Button(
            toolbar, text="回收站", width=16, command=self._toggle_trash_view
        )
        self.btn_view_switch.pack(side="right", padx=(0, 8))

        # 列表
        body = ttk.Frame(frame, padding=(8, 0))
        body.pack(fill="both", expand=True)

        cols = ("title", "username", "tags", "updated")
        self.tree = ttk.Treeview(body, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("title", text="标题")
        self.tree.heading("username", text="账号")
        self.tree.heading("tags", text="标签")
        self.tree.heading("updated", text="更新")
        self.tree.column("title", width=220)
        self.tree.column("username", width=220)
        self.tree.column("tags", width=130)
        self.tree.column("updated", width=130)
        self.tree.pack(side="left", fill="both", expand=True)

        sb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        sb.pack(side="left", fill="y")
        self.tree.config(yscrollcommand=sb.set)

        self.tree.bind("<Double-1>", lambda e: self.do_edit())
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._update_buttons())

        # 右键菜单
        self.ctx_menu = tk.Menu(self.root, tearoff=0)
        self.ctx_menu.add_command(label="查看", command=self.do_view)
        self.ctx_menu.add_command(label="编辑", command=self.do_edit)
        self.ctx_menu.add_command(label="复制账号", command=lambda: self.do_copy("username"))
        self.ctx_menu.add_command(label="复制密码", command=lambda: self.do_copy("password"))
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="删除", command=self.do_delete)
        self.ctx_menu.add_command(label="恢复", command=self.do_restore)
        self.ctx_menu.add_command(label="彻底删除", command=self.do_purge)
        self.tree.bind("<Button-3>", self._show_ctx)

        # 底部按钮
        btnbar = ttk.Frame(frame, padding=(8, 6))
        btnbar.pack(fill="x")
        self.btn_edit = ttk.Button(btnbar, text="编辑", command=self.do_edit, state="disabled")
        self.btn_edit.pack(side="left", padx=2)
        self.btn_delete = ttk.Button(btnbar, text="删除", command=self.do_delete, state="disabled")
        self.btn_delete.pack(side="left", padx=2)
        self.btn_restore = ttk.Button(btnbar, text="恢复", command=self.do_restore, state="disabled")
        self.btn_restore.pack(side="left", padx=2)
        self.btn_copy_user = ttk.Button(btnbar, text="复制账号",
                                        command=lambda: self.do_copy("username"), state="disabled")
        self.btn_copy_user.pack(side="left", padx=2)
        self.btn_copy_pw = ttk.Button(btnbar, text="复制密码",
                                      command=lambda: self.do_copy("password"), state="disabled")
        self.btn_copy_pw.pack(side="left", padx=2)

        return frame

    # ---------- 界面切换 ----------

    def _show_lock_frame(self):
        self.main_frame.pack_forget()
        self.lock_frame.pack(fill="both", expand=True)
        self._update_lock_hint()
        self.lock_pw_entry.focus_set()

    def _check_initial_state(self):
        """启动时自动检测：如果没有库文件，直接引导用户新建。"""
        if not self.vault.exists():
            ans = messagebox.askyesno(
                "欢迎使用",
                "未检测到保险库文件，是否立即新建一个全新的保险库？\n\n"
                "（如果是因为误删了库文件，请点“否”，然后通过菜单恢复文件或从密钥备份包恢复）"
            )
            if ans:
                self._create_vault()
            else:
                self._update_lock_hint()
        else:
            self._update_lock_hint()

    def _show_main_frame(self):
        self.lock_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)

    def _update_lock_hint(self):
        kf = find_keyfile()
        if kf:
            self.lock_hint.config(text=f"检测到U盘: {os.path.dirname(kf)}", foreground="#080")
        else:
            if self.vault.exists():
                self.lock_hint.config(text="未检测到含 .vault_key 的U盘，请插入U盘", foreground="#c00")
            else:
                self.lock_hint.config(text="未找到保险库文件，请点击下方按钮新建", foreground="#c00")

        # 库文件不存在时按钮显示"创建新库"
        if self.vault.exists():
            self.unlock_btn.config(text="解 锁")
        else:
            self.unlock_btn.config(text="新建保险库")

    def _toggle_lock_pw(self):
        self.lock_pw_entry.config(show="" if self.lock_show_pw.get() else "*")

    def _toggle_trash_view(self):
        """工具栏按钮：在账号列表和回收站之间切换。"""
        self.show_trash = not self.show_trash
        self.refresh_list()
        if self.show_trash:
            self.status_var.set("回收站 - 删除的条目在这里，可恢复或彻底删除")
        else:
            self.status_var.set(f"账号列表 - {len(self._visible_entries())} 条记录")


    # ---------- 后台监控 ----------

    def _start_monitors(self):
        self.root.after(1000, self._tick_keyfile)
        self.root.after(5000, self._tick_idle)

    def _tick_keyfile(self):
        """每秒检查：已解锁状态下U盘是否还在；锁定状态下刷新提示。"""
        if not self.locked and self.keyfile_path and not os.path.exists(self.keyfile_path):
            self.lock("U盘已拔出")
        elif self.locked:
            self._update_lock_hint()
        self.root.after(1500, self._tick_keyfile)

    def _tick_idle(self):
        """每 5 秒检查空闲时间。"""
        if not self.locked and time.time() - self.last_activity > IDLE_TIMEOUT:
            self.lock("空闲超时")
        self.root.after(5000, self._tick_idle)

    def _record_activity(self, event=None):
        self.last_activity = time.time()

    # ---------- 解锁 / 创建 / 锁定 ----------

    def _on_unlock(self):
        # 库文件不存在 -> 走创建流程
        if not self.vault.exists():
            self._create_vault()
            return

        kf = find_keyfile()
        if not kf:
            messagebox.showwarning(
                "提示",
                "未检测到含 .vault_key 的U盘，请插入U盘后重试。\n\n"
                "若U盘已丢失，请使用菜单「安全 → 从备份包恢复密钥」恢复到新U盘。"
            )
            return

        pw = self.lock_pw_var.get()
        if not pw:
            self.lock_msg.config(text="请输入主密码")
            return

        try:
            kf_bytes = read_keyfile(kf)
            info = self.vault.unlock(pw, kf_bytes)
        except WrongPassword:
            self.lock_msg.config(text="主密码错误")
            self.lock_pw_var.set("")
            self.lock_pw_entry.focus_set()
            return
        except WrongKeyfile:
            self.lock_msg.config(text="U盘密钥不匹配（插错了U盘？）")
            return
        except VaultError as e:
            self.lock_msg.config(text=str(e))
            return

        self._apply_unlocked(info, kf, kf_bytes)

    def _create_vault(self):
        """首次创建流程：选U盘目录 -> 设主密码 -> 写 keyfile -> 建库。"""
        # 提示用户准备U盘
        messagebox.showinfo(
            "准备新建",
            "接下来请选择作为「U盘钥匙」的U盘根目录。\n\n"
            "如果不插U盘，也可以选择一个固定文件夹（如D盘某目录）作为虚拟钥匙。\n"
            "请确保所选目录中没有其他重要文件被误覆盖。"
        )

        mount = filedialog.askdirectory(
            parent=self.root, title="请选择U盘根目录（用于存放 .vault_key）"
        )
        if not mount:
            self.status_var.set("已取消新建")
            self._update_lock_hint()  # 刷新界面
            return
        if not mount:
            return
        kf_path = os.path.join(mount, ".vault_key")
        if os.path.exists(kf_path):
            if not messagebox.askyesno("确认", f"{kf_path} 已存在，覆盖会让旧库无法解密！继续？"):
                return

        pw1 = simpledialog.askstring("设置主密码", "设置主密码（至少 8 位）:",
                                     show="*", parent=self.root)
        if not pw1:
            return
        if len(pw1) < 8:
            messagebox.showwarning("提示", "主密码至少 8 位")
            return
        pw2 = simpledialog.askstring("确认主密码", "再次输入主密码:",
                                     show="*", parent=self.root)
        if pw1 != pw2:
            messagebox.showwarning("提示", "两次输入不一致")
            return
        if not messagebox.askyesno(
            "警告",
            "主密码遗忘将导致数据永久无法恢复，没有后门。\n确认使用该主密码？"
        ):
            return

        try:
            kf_file = make_keyfile_file()
            with open(kf_path, "wb") as f:
                f.write(kf_file)
            kf_bytes = parse_keyfile_file(kf_file)
        except Exception as e:
            messagebox.showerror("写入失败", str(e))
            return

        try:
            info = self.vault.create(pw1, kf_bytes, {"next_id": 1, "entries": []})
        except Exception as e:
            messagebox.showerror("创建失败", str(e))
            return

        self._apply_unlocked(info, kf_path, kf_bytes)
        messagebox.showinfo(
            "完成",
            f"库文件已创建: {self.vault.path}\n"
            f"密钥已写入: {kf_path}\n\n"
            "建议立即从「安全」菜单导出密钥备份包，以防U盘丢失。"
        )

    def _apply_unlocked(self, info, keyfile_path, keyfile_bytes):
        """把 unlock/create 返回的运行时状态装进对象并切换到主界面。"""
        self.k1 = info["k1"]
        self.salt = info["salt"]
        self.params = info["params"]
        self.final_key = info["final_key"]
        self.header = info["header"]
        self.data = info["data"]
        self.keyfile_path = keyfile_path
        self.keyfile_bytes = keyfile_bytes
        self.locked = False
        self.last_activity = time.time()

        self.lock_pw_var.set("")
        self.lock_msg.config(text="")
        self.show_trash = False

        self.refresh_list()
        self._show_main_frame()
        self.status_var.set(
            f"已解锁 - {len(self._visible_entries())} 条记录 - U盘: {os.path.dirname(keyfile_path)}"
        )

    def lock(self, reason="手动锁定"):
        """清空所有敏感数据并回到解锁界面。"""
        if self.locked:
            return
        self.locked = True
        self.k1 = None
        self.salt = None
        self.params = None
        self.final_key = None
        self.header = None
        self.data = None
        self.keyfile_bytes = None
        self.tree.delete(*self.tree.get_children())
        self.lock_pw_var.set("")
        self.lock_msg.config(text=f"已锁定（{reason}）")
        self._show_lock_frame()
        self.status_var.set(f"已锁定（{reason}）")

    # ---------- 列表与选择 ----------

    def _visible_entries(self):
        if not self.data:
            return []
        return [e for e in self.data["entries"] if e["deleted"] == self.show_trash]

    def refresh_list(self):
        if self.locked or self.data is None:
            return
        self.tree.delete(*self.tree.get_children())
        kw = self.search_var.get().strip().lower()
        for e in self.data["entries"]:
            if e["deleted"] != self.show_trash:
                continue
            if kw and not self._match(e, kw):
                continue
            self.tree.insert("", "end", iid=str(e["id"]), values=(
                e["title"], e["username"], ",".join(e["tags"]), e["updated"][:10]
            ))

        # 更新视图切换按钮的文字
        trash_count = sum(1 for e in self.data["entries"] if e["deleted"])
        if self.show_trash:
            self.btn_view_switch.config(text="← 返回账号列表", width=16)
            self.btn_add.config(state="disabled")
        else:
            self.btn_view_switch.config(
                text=f"回收站 ({trash_count})" if trash_count else "回收站", width=16
            )
            self.btn_add.config(state="normal")

        self._update_buttons()

    def _match(self, e, kw):
        return (
            kw in e["title"].lower()
            or kw in e["username"].lower()
            or kw in e["url"].lower()
            or kw in e["notes"].lower()
            or any(kw in t.lower() for t in e["tags"])
        )

    def _get_selected(self):
        if self.locked or self.data is None:
            return None
        sel = self.tree.selection()
        if not sel:
            return None
        try:
            eid = int(sel[0])
        except ValueError:
            return None
        for e in self.data["entries"]:
            if e["id"] == eid:
                return e
        return None

    def _update_buttons(self):
        sel = self._get_selected()
        if sel is None:
            for btn in (self.btn_edit, self.btn_delete, self.btn_restore,
                        self.btn_copy_user, self.btn_copy_pw):
                btn.config(state="disabled")
            return
        for btn in (self.btn_edit, self.btn_copy_user, self.btn_copy_pw):
            btn.config(state="normal")
        if sel["deleted"]:
            self.btn_delete.config(state="disabled")
            self.btn_restore.config(state="normal")
        else:
            self.btn_delete.config(state="normal")
            self.btn_restore.config(state="disabled")

    def _show_ctx(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.ctx_menu.tk_popup(event.x_root, event.y_root)

    def save(self):
        try:
            self.vault.save(self.final_key, self.header, self.data)
        except Exception as e:
            messagebox.showerror("保存失败", str(e))

    # ---------- 条目操作 ----------

    def do_add(self):
        if self.show_trash:
            messagebox.showinfo("提示", "请先返回账号列表再新增条目", parent=self.root)
            return
        dlg = EntryDialog(self.root, "新增条目")
        if dlg.result is None:
            return
        e = {
            **dlg.result,
            "id": self.data["next_id"],
            "created": now_iso(),
            "updated": now_iso(),
            "deleted": False,
        }
        self.data["next_id"] += 1
        self.data["entries"].append(e)
        self.save()
        self.refresh_list()
        self.status_var.set(f"已添加: {e['title']}")

    def do_edit(self):
        e = self._get_selected()
        if not e:
            return
        dlg = EntryDialog(self.root, "编辑条目", e)
        if dlg.result is None:
            return
        e.update(dlg.result)
        e["updated"] = now_iso()
        self.save()
        self.refresh_list()
        self.status_var.set(f"已保存: {e['title']}")

    def do_view(self):
        e = self._get_selected()
        if not e:
            return
        lines = [
            f"标题: {e['title']}",
            f"账号: {e['username']}",
            f"密码: {e['password']}",
        ]
        if e["url"]:
            lines.append(f"网址: {e['url']}")
        if e["tags"]:
            lines.append(f"标签: {', '.join(e['tags'])}")
        if e["notes"]:
            lines.append(f"备注: {e['notes']}")
        lines.append(f"更新: {e['updated']}")
        messagebox.showinfo(e["title"], "\n".join(lines), parent=self.root)

    def do_copy(self, field):
        e = self._get_selected()
        if not e:
            return
        text = e[field]
        if not text:
            self.status_var.set("该字段为空")
            return
        if copy_clipboard(text):
            label = "账号" if field == "username" else "密码"
            self.status_var.set(f"已复制{label}（{CLIPBOARD_CLEAR} 秒后清空）")
        else:
            messagebox.showwarning("提示", "无法访问剪贴板（未安装 pyperclip？）")

    def do_delete(self):
        e = self._get_selected()
        if not e or e["deleted"]:
            return
        if not messagebox.askyesno("确认", f"删除「{e['title']}」？\n（可稍后从回收站恢复）"):
            return
        e["deleted"] = True
        e["updated"] = now_iso()
        self.save()
        self.refresh_list()
        self.status_var.set(f"已移入回收站: {e['title']}")

    def do_restore(self):
        e = self._get_selected()
        if not e or not e["deleted"]:
            return
        e["deleted"] = False
        e["updated"] = now_iso()
        self.save()
        self.refresh_list()
        self.status_var.set(f"已恢复: {e['title']}")

    def do_purge(self):
        e = self._get_selected()
        if not e or not e["deleted"]:
            return
        if not messagebox.askyesno("确认", f"彻底删除「{e['title']}」？\n不可恢复！"):
            return
        self.data["entries"].remove(e)
        self.save()
        self.refresh_list()
        self.status_var.set(f"已彻底删除: {e['title']}")

    # ---------- 文件相关 ----------

    def _confirm_password(self):
        """敏感操作前二次验证。返回密码字符串或 None。"""
        pw = simpledialog.askstring("确认", "请输入主密码以确认:",
                                    show="*", parent=self.root)
        if not pw:
            return None
        k1 = derive_k1(pw, self.salt, self.params)
        if hmac.compare_digest(check_k1(k1), b64d(self.header["check_k1"])):
            return pw
        messagebox.showerror("错误", "主密码错误")
        return None

    def do_new_vault(self):
        """用户主动新建保险库（会覆盖原库）。"""
        if not self.locked:
            ans = messagebox.askyesno(
                "危险操作",
                "你现在处于解锁状态！\n"
                "新建保险库将【覆盖】当前正在使用的保险库，\n"
                "且所有账号密码将永久丢失！\n\n"
                "确定要继续吗？",
                icon="warning"
            )
            if not ans:
                return
            self.lock("准备新建保险库")
        else:
            if self.vault.exists():
                ans = messagebox.askyesno(
                    "警告",
                    "当前已存在一个保险库文件！\n"
                    "继续新建将【覆盖】原有保险库，导致旧数据永久丢失！\n\n"
                    "确定要新建吗？",
                    icon="warning"
                )
                if not ans:
                    return

        self._create_vault()

    def do_backup(self):
        if self.locked:
            return
        path = filedialog.asksaveasfilename(
            parent=self.root, title="备份库文件",
            defaultextension=".dat", initialfile="vault_backup.dat",
            filetypes=[("Vault 文件", "*.dat"), ("所有文件", "*.*")],
        )
        if not path:
            return
        try:
            import shutil
            shutil.copy2(self.vault.path, path)
        except Exception as e:
            messagebox.showerror("备份失败", str(e))
            return
        self.status_var.set(f"已备份到 {path}")

    def do_export(self, fmt):
        if self.locked:
            return
        if not self._confirm_password():
            return
        path = filedialog.asksaveasfilename(
            parent=self.root, title="导出明文",
            defaultextension=f".{fmt}", initialfile=f"passwords.{fmt}",
            filetypes=[(f"{fmt.upper()} 文件", f"*.{fmt}"), ("所有文件", "*.*")],
        )
        if not path:
            return
        entries = [e for e in self.data["entries"] if not e["deleted"]]
        try:
            if fmt == "csv":
                import csv
                with open(path, "w", newline="", encoding="utf-8-sig") as f:
                    w = csv.writer(f)
                    w.writerow(["标题", "账号", "密码", "网址", "标签", "备注"])
                    for e in entries:
                        w.writerow([e["title"], e["username"], e["password"],
                                    e["url"], ",".join(e["tags"]), e["notes"]])
            else:
                import json
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(entries, f, ensure_ascii=False, indent=2)
        except Exception as e:
            messagebox.showerror("导出失败", str(e))
            return
        messagebox.showwarning(
            "注意",
            f"已导出 {len(entries)} 条明文记录到:\n{path}\n\n请妥善保管并及时删除该文件。"
        )

    def do_import(self):
        if self.locked:
            return
        path = filedialog.askopenfilename(
            parent=self.root, title="选择 CSV 文件",
            filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")],
        )
        if not path:
            return
        try:
            import csv
            added = 0
            with open(path, "r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    title = (row.get("标题") or row.get("title") or "").strip()
                    if not title:
                        continue
                    tags_raw = row.get("标签") or row.get("tags") or ""
                    self.data["entries"].append({
                        "id": self.data["next_id"],
                        "title": title,
                        "username": (row.get("账号") or row.get("username") or "").strip(),
                        "password": (row.get("密码") or row.get("password") or "").strip(),
                        "url": (row.get("网址") or row.get("url") or "").strip(),
                        "tags": [t.strip() for t in tags_raw.split(",") if t.strip()],
                        "notes": (row.get("备注") or row.get("notes") or "").strip(),
                        "created": now_iso(),
                        "updated": now_iso(),
                        "deleted": False,
                    })
                    self.data["next_id"] += 1
                    added += 1
            self.save()
            self.refresh_list()
            self.status_var.set(f"已导入 {added} 条记录")
        except Exception as e:
            messagebox.showerror("导入失败", str(e))

    # ---------- 安全相关 ----------

    def do_change_password(self):
        if self.locked:
            return
        if not self._confirm_password():
            return
        pw1 = simpledialog.askstring("新主密码", "设置新主密码（至少 8 位）:",
                                     show="*", parent=self.root)
        if not pw1:
            return
        if len(pw1) < 8:
            messagebox.showwarning("提示", "主密码至少 8 位")
            return
        pw2 = simpledialog.askstring("确认", "再次输入新主密码:",
                                     show="*", parent=self.root)
        if pw1 != pw2:
            messagebox.showwarning("提示", "两次输入不一致")
            return
        try:
            info = self.vault.change_password(self.keyfile_bytes, pw1, self.data)
        except Exception as e:
            messagebox.showerror("修改失败", str(e))
            return
        self.k1 = info["k1"]
        self.salt = info["salt"]
        self.params = info["params"]
        self.final_key = info["final_key"]
        self.header = info["header"]
        messagebox.showinfo("完成", "主密码已修改。\n\n旧的密钥备份包需用旧密码才能解开。")

    def do_new_keyfile(self):
        if self.locked:
            return
        if not messagebox.askyesno("确认",
                                    "将生成新的 keyfile 并重新加密库文件。\n旧U盘将失效，确定继续？"):
            return
        mount = filedialog.askdirectory(parent=self.root, title="选择目标U盘根目录")
        if not mount:
            return
        kf_path = os.path.join(mount, ".vault_key")
        if os.path.exists(kf_path):
            if not messagebox.askyesno("确认", f"{kf_path} 已存在，覆盖？"):
                return
        try:
            kf_file = make_keyfile_file()
            with open(kf_path, "wb") as f:
                f.write(kf_file)
            new_kf = parse_keyfile_file(kf_file)
            info = self.vault.change_keyfile(self.k1, new_kf, self.header, self.data)
        except Exception as e:
            messagebox.showerror("更换失败", str(e))
            return
        self.final_key = info["final_key"]
        self.header = info["header"]
        self.keyfile_bytes = new_kf
        self.keyfile_path = kf_path
        messagebox.showinfo("完成",
                            f"密钥已更换并写入 {kf_path}\n\n"
                            "旧U盘已失效，建议立即重新导出密钥备份包。")

    def do_destroy_vault(self):
        """彻底销毁保险库（需验证主密码和密钥）。"""
        if self.locked:
            return

        # 1. 检查U盘是否还插着（必须删掉U盘上的密钥才算销毁）
        if not self.keyfile_path or not os.path.exists(self.keyfile_path):
            messagebox.showerror(
                "无法销毁",
                "未检测到当前U盘上的密钥文件！\n\n"
                "为了防止数据残留，必须插着原U盘才能执行销毁操作。",
                parent=self.root
            )
            return

        # 2. 第一次高危警告
        ans = messagebox.askyesno(
            "⚠️ 极度危险操作 ⚠️",
            "你即将执行【销毁保险库】！\n\n"
            "这会彻底删除：\n"
            "  1. 电脑上的库文件 (vault.dat)\n"
            "  2. U盘上的密钥文件 (.vault_key)\n"
            "  3. 所有本地自动历史备份\n\n"
            "所有账号密码将永久丢失，没有任何后门可以恢复！\n\n"
            "确定要继续吗？",
            icon="warning",
            parent=self.root
        )
        if not ans:
            return

        # 3. 验证主密码
        if not self._confirm_password():
            return

        # 4. 执行删除
        try:
            import shutil

            # 删除库文件
            if os.path.exists(self.vault.path):
                os.remove(self.vault.path)

            # 删除备份目录
            backup_dir = os.path.join(os.path.dirname(os.path.abspath(self.vault.path)), "backups")
            if os.path.exists(backup_dir):
                shutil.rmtree(backup_dir)

            # 删除U盘密钥
            if os.path.exists(self.keyfile_path):
                os.remove(self.keyfile_path)

        except Exception as e:
            messagebox.showerror(
                "销毁失败",
                f"删除文件时出错（可能文件被占用，请关闭杀毒软件或手动删除）：\n{e}",
                parent=self.root
            )
            return

        # 5. 销毁成功，回到初始锁定状态
        self.lock("保险库已销毁")
        messagebox.showinfo(
            "已销毁",
            "保险库、本地备份与U盘密钥已彻底删除。\n程序将回到初始状态。",
            parent=self.root
        )
        # 刷新界面并触发“无库文件”的初始提示
        self._check_initial_state()

    def do_key_backup(self):
        if self.locked:
            return
        pw = self._confirm_password()
        if not pw:
            return
        path = filedialog.asksaveasfilename(
            parent=self.root, title="保存密钥备份包",
            defaultextension=".vkb", initialfile="keybackup.vkb",
            filetypes=[("Vault 备份包", "*.vkb"), ("所有文件", "*.*")],
        )
        if not path:
            return
        try:
            blob = make_key_backup(pw, self.keyfile_bytes)
            with open(path, "wb") as f:
                f.write(blob)
        except Exception as e:
            messagebox.showerror("导出失败", str(e))
            return
        messagebox.showinfo("完成",
                            f"密钥备份包已保存到:\n{path}\n\n"
                            "请妥善保管：此文件 + 导出时使用的主密码，可在U盘丢失后恢复密钥。")

    def do_restore_key(self):
        """从备份包恢复密钥到新U盘。锁定状态下也可用。"""
        path = filedialog.askopenfilename(
            parent=self.root, title="选择密钥备份包",
            filetypes=[("Vault 备份包", "*.vkb"), ("所有文件", "*.*")],
        )
        if not path:
            return
        pw = simpledialog.askstring("主密码", "请输入导出该备份包时的主密码:",
                                    show="*", parent=self.root)
        if not pw:
            return
        try:
            with open(path, "rb") as f:
                blob = f.read()
            keyfile_bytes = open_key_backup(pw, blob)
        except VaultError as e:
            messagebox.showerror("错误", str(e))
            return
        except Exception as e:
            messagebox.showerror("读取失败", str(e))
            return

        mount = filedialog.askdirectory(parent=self.root, title="选择目标U盘根目录")
        if not mount:
            return
        target = os.path.join(mount, ".vault_key")
        if os.path.exists(target):
            if not messagebox.askyesno("确认", f"{target} 已存在，覆盖？"):
                return
        try:
            with open(target, "wb") as f:
                f.write(KEYFILE_MAGIC + keyfile_bytes)
        except Exception as e:
            messagebox.showerror("写入失败", str(e))
            return

        self._update_lock_hint()
        messagebox.showinfo("完成",
                            f"已恢复 keyfile 到:\n{target}\n\n"
                            "现在可以解锁使用。\n建议解锁后执行「更换U盘密钥」让旧的丢失U盘彻底作废。")

    # ---------- 杂项 ----------

    def show_help(self):
        messagebox.showinfo(
            "使用说明",
            "【解锁】\n"
            "  插入含 .vault_key 的U盘 -> 输入主密码 -> 回车\n\n"
            "【日常操作】\n"
            "  双击条目编辑；右键菜单可复制密码、删除等\n"
            "  顶部搜索框可实时过滤\n\n"
            "【安全】\n"
            "  U盘拔出或空闲 10 分钟会自动锁定\n"
            "  复制密码 30 秒后自动清空剪贴板\n\n"
            "【备份】\n"
            "  文件 → 备份库文件：加密备份，换电脑用\n"
            "  安全 → 导出密钥备份包：U盘丢了用它恢复\n\n"
            "【U盘丢失怎么办】\n"
            "  菜单 安全 → 从备份包恢复密钥 -> 选备份包和新U盘"
        )

    def on_close(self):
        self.lock("退出")
        self.root.destroy()