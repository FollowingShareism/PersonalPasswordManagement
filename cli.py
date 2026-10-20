"""cli.py — 交互式命令行界面"""
from __future__ import annotations

import csv
import getpass
import hmac
import json
import os
import shlex
import shutil
import threading
import time

import psutil

from crypto_layer import (
    KEYFILE_MAGIC,
    VaultError,
    WrongKeyfile,
    WrongPassword,
    b64d,
    check_k1,
    derive_k1,
    make_key_backup,
    make_keyfile_file,
    open_key_backup,
    parse_keyfile_file,
)
from storage import VaultFile

def secure_input(prompt: str = "") -> str:
    """带 * 回显的密码输入。Windows 用 msvcrt 逐字符读取并回显 *。"""
    import sys
    if sys.platform == "win32":
        import msvcrt
        print(prompt, end="", flush=True)
        chars = []
        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):          # 回车，结束输入
                print()
                break
            elif ch == "\x03":              # Ctrl+C
                print("^C")
                raise KeyboardInterrupt
            elif ch in ("\x08", "\x7f"):    # 退格：删掉一个 *
                if chars:
                    chars.pop()
                    print("\b \b", end="", flush=True)
            elif ch == "\x1a":              # Ctrl+Z
                raise EOFError
            else:
                chars.append(ch)
                print("*", end="", flush=True)
        return "".join(chars)
    else:
        # 非 Windows（mac/Linux）用 termios 关闭回显再手动打 *
        import tty, termios
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            print(prompt, end="", flush=True)
            chars = []
            while True:
                ch = sys.stdin.read(1)
                if ch in ("\r", "\n"):
                    print()
                    break
                elif ch == "\x03":
                    raise KeyboardInterrupt
                elif ch in ("\x08", "\x7f"):
                    if chars:
                        chars.pop()
                        print("\b \b", end="", flush=True)
                elif ch == "\x04":
                    raise EOFError
                else:
                    chars.append(ch)
                    print("*", end="", flush=True)
            return "".join(chars)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

IDLE_TIMEOUT = 600  # 10 分钟
CLIPBOARD_CLEAR = 30


# ---------- 工具函数 ----------

def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def strip_quotes(s: str) -> str:
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def split_args(line: str):
    try:
        parts = shlex.split(line, posix=False)
    except ValueError:
        parts = line.split()
    return [strip_quotes(p) for p in parts]


def list_mounts():
    out = []
    for p in psutil.disk_partitions(all=False):
        try:
            out.append(p.mountpoint)
        except Exception:
            pass
    return out


def choose_mount():
    mounts = list_mounts()
    if not mounts:
        print("未检测到任何磁盘分区")
        return None
    print("可用磁盘：")
    for i, m in enumerate(mounts, 1):
        kf = os.path.join(m, ".vault_key")
        mark = "  [已有 keyfile]" if os.path.isfile(kf) else ""
        print(f"  {i}) {m}{mark}")
    while True:
        s = input("请选择U盘编号（q 取消）: ").strip()
        if s.lower() == "q":
            return None
        if s.isdigit() and 1 <= int(s) <= len(mounts):
            return mounts[int(s) - 1]
        print("输入无效")


def find_keyfile():
    for mount in list_mounts():
        try:
            p = os.path.join(mount, ".vault_key")
            if os.path.isfile(p):
                return p
        except Exception:
            continue
    return None


def read_keyfile(path: str) -> bytes:
    with open(path, "rb") as f:
        return parse_keyfile_file(f.read())


def prompt_new_password() -> str:
    while True:
        p1 = secure_input("设置主密码（至少 8 位）: ")
        if len(p1) < 8:
            print("主密码至少 8 位")
            continue
        p2 = secure_input("再次输入: ")
        if p1 != p2:
            print("两次输入不一致")
            continue
        print("⚠️  警告：主密码遗忘将导致数据永久无法恢复，没有后门。")
        if input("确认使用该主密码？(y/N): ").strip().lower() == "y":
            return p1


def generate_password(length: int = 20) -> str:
    import secrets
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


def copy_to_clipboard(text: str, timeout: int = CLIPBOARD_CLEAR) -> None:
    try:
        import pyperclip
        pyperclip.copy(text)
    except Exception:
        print("（未安装 pyperclip，无法复制到剪贴板。pip install pyperclip）")
        return

    def clear():
        time.sleep(timeout)
        try:
            if pyperclip.paste() == text:
                pyperclip.copy("")
        except Exception:
            pass

    threading.Thread(target=clear, daemon=True).start()


def empty_data() -> dict:
    return {"next_id": 1, "entries": []}


# ---------- 主应用 ----------

class App:
    def __init__(self, vault_path: str):
        self.vault = VaultFile(vault_path)
        self.keyfile_path = None
        self.keyfile_bytes = None
        self.k1 = None
        self.salt = None
        self.params = None
        self.final_key = None
        self.header = None
        self.data = None
        self.locked = True
        self.last_activity = time.time()
        self.stop_event = threading.Event()

    # ----- 生命周期 -----

    def run(self):
        self._start_monitor()
        if not self.vault.exists():
            if not self.setup_new():
                return
        else:
            if not self.unlock():
                return
        self.repl()

    def _start_monitor(self):
        threading.Thread(target=self._monitor, daemon=True).start()

    def _monitor(self):
        while not self.stop_event.is_set():
            if not self.locked:
                if self.keyfile_path and not os.path.exists(self.keyfile_path):
                    self.lock("U盘已拔出")
                elif time.time() - self.last_activity > IDLE_TIMEOUT:
                    self.lock("空闲超时")
            time.sleep(1)

    def lock(self, reason: str, force: bool = False):
        if self.locked and not force:
            return
        self.locked = True
        self.k1 = None
        self.salt = None
        self.params = None
        self.final_key = None
        self.header = None
        self.data = None
        self.keyfile_bytes = None
        if not force:
            print(f"\n[已锁定] {reason}")

    def _apply(self, info: dict, keyfile_path: str, keyfile_bytes: bytes):
        #"""把 unlock/create 返回的运行时状态装进对象。"""
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

    # ----- 初始化 -----

    def setup_new(self) -> bool:
        print("=== 首次初始化 ===")
        print("未找到库文件，将创建新的密码库。")
        mount = choose_mount()
        if not mount:
            return False
        kf_path = os.path.join(mount, ".vault_key")
        if os.path.exists(kf_path):
            if input(f"{kf_path} 已存在，覆盖会让旧库无法解密！继续？(y/N): ").strip().lower() != "y":
                return False
        pw = prompt_new_password()
        kf_file = make_keyfile_file()
        with open(kf_path, "wb") as f:
            f.write(kf_file)
        kf_bytes = parse_keyfile_file(kf_file)
        info = self.vault.create(pw, kf_bytes, empty_data())
        self._apply(info, kf_path, kf_bytes)
        print(f"✅ 库文件已创建: {self.vault.path}")
        print(f"✅ 密钥已写入: {kf_path}")
        print("建议立即导出密钥备份包（命令 keybackup），以防U盘丢失。")
        return True

    # ----- 解锁 -----

    def unlock(self) -> bool:
        """解锁循环：没找到U盘就等，找到了就试密码，密码错可以重试。"""
        while True:
            kf = find_keyfile()
            if not kf:
                print("未检测到含 .vault_key 的U盘，请插入U盘（Ctrl+C 退出）")
                time.sleep(2)
                continue

            pw = secure_input("主密码: ")
            try:
                kf_bytes = read_keyfile(kf)
                info = self.vault.unlock(pw, kf_bytes)
            except WrongPassword as e:
                print(f"❌ {e}")
                continue
            except WrongKeyfile as e:
                print(f"❌ {e}")
                continue
            except VaultError as e:
                print(f"❌ {e}")
                return False

            self._apply(info, kf, kf_bytes)
            n = len([e for e in self.data["entries"] if not e["deleted"]])
            print(f"✅ 解锁成功，共 {n} 条记录（U盘: {os.path.dirname(kf)}）")
            return True


    # ----- REPL -----

    def repl(self):
        print("输入 help 查看命令，quit 退出。")
        handlers = {
            "help": self.cmd_help,
            "list": self.cmd_list,
            "ls": self.cmd_list,
            "search": self.cmd_search,
            "get": self.cmd_get,
            "add": self.cmd_add,
            "edit": self.cmd_edit,
            "del": self.cmd_del,
            "rm": self.cmd_del,
            "restore": self.cmd_restore,
            "purge": self.cmd_purge,
            "gen": self.cmd_gen,
            "export": self.cmd_export,
            "import": self.cmd_import,
            "backup": self.cmd_backup,
            "keybackup": self.cmd_keybackup,
            "restore-key": self.cmd_restore_key,
            "passwd": self.cmd_passwd,
            "newkey": self.cmd_newkey,
            "lock": self.cmd_lock,
        }
        while True:
            if self.locked:
                try:
                    if not self.unlock():
                        break
                except KeyboardInterrupt:
                    break
                continue
            try:
                line = input("vault> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            self.last_activity = time.time()
            if not line:
                continue
            if self.locked:
                continue
            parts = split_args(line)
            if not parts:
                continue
            cmd, args = parts[0].lower(), parts[1:]
            if cmd in ("quit", "exit", "q"):
                break
            handler = handlers.get(cmd)
            if not handler:
                print(f"未知命令: {cmd}（输入 help 查看命令）")
                continue
            try:
                handler(args)
            except Exception as e:
                print(f"错误: {e}")
        self.lock("退出", force=True)
        self.stop_event.set()
        print("已退出。")

    # ----- 通用 -----

    def save(self):
        self.vault.save(self.final_key, self.header, self.data)

    def confirm_password(self):
        pw = secure_input("请输入主密码以确认: ")
        k1 = derive_k1(pw, self.salt, self.params)
        if hmac.compare_digest(check_k1(k1), b64d(self.header["check_k1"])):
            return pw
        print("❌ 主密码错误")
        return None

    def find_entry(self, key: str):
        entries = [e for e in self.data["entries"] if not e["deleted"]]
        if key.isdigit():
            for e in entries:
                if e["id"] == int(key):
                    return e
            print(f"未找到 ID={key}")
            return None
        kl = key.lower()
        matches = [
            e for e in entries
            if kl in e["title"].lower() or kl in e["username"].lower()
        ]
        if not matches:
            print("未找到匹配记录")
            return None
        if len(matches) == 1:
            return matches[0]
        print("匹配到多条，请用 ID 指定：")
        for e in matches:
            print(f"  [{e['id']}] {e['title']}  ({e['username']})")
        return None

    # ----- 命令实现 -----

    def cmd_help(self, args):
        print("""命令列表：
  list [-t 标签] [--trash]   列出条目 / 回收站
  search <关键字>             搜索
  get <ID或标题>              查看并复制密码到剪贴板
  add                        新增条目（交互式）
  edit <ID或标题>             编辑条目
  del <ID>                   移入回收站
  restore <ID>               从回收站恢复
  purge <ID>                 彻底删除
  gen [长度]                  生成随机密码并复制
  export csv|json <路径>      导出明文（需主密码确认）
  import csv <路径>           从 CSV 导入
  backup [路径]               备份库文件
  keybackup [路径]            导出密钥备份包
  restore-key <备份包>        从备份包恢复 keyfile 到U盘
  passwd                     修改主密码
  newkey                     更换U盘密钥
  lock                       手动锁定
  quit / exit / q            退出""")

    def cmd_list(self, args):
        show_trash = "--trash" in args
        tag = None
        if "-t" in args:
            i = args.index("-t")
            if i + 1 < len(args):
                tag = args[i + 1]
        entries = [e for e in self.data["entries"] if e["deleted"] == show_trash]
        if tag:
            entries = [e for e in entries if tag in e["tags"]]
        if not entries:
            print("（无记录）")
            return
        header = f"{'ID':<5}{'标题':<22}{'账号':<24}{'标签':<14}更新"
        print(header)
        print("-" * len(header))
        for e in entries:
            print(
                f"{e['id']:<5}"
                f"{e['title'][:20]:<22}"
                f"{e['username'][:22]:<24}"
                f"{','.join(e['tags'])[:12]:<14}"
                f"{e['updated'][:10]}"
            )

    def cmd_search(self, args):
        if not args:
            print("用法: search <关键字>")
            return
        kw = args[0].lower()
        res = [
            e for e in self.data["entries"]
            if not e["deleted"] and (
                kw in e["title"].lower()
                or kw in e["username"].lower()
                or kw in e["url"].lower()
                or kw in e["notes"].lower()
                or any(kw in t.lower() for t in e["tags"])
            )
        ]
        if not res:
            print("未找到")
            return
        for e in res:
            print(f"[{e['id']}] {e['title']}  账号: {e['username']}  标签: {','.join(e['tags'])}")

    def cmd_get(self, args):
        if not args:
            print("用法: get <ID或标题>")
            return
        e = self.find_entry(args[0])
        if not e:
            return
        print(f"ID   : {e['id']}")
        print(f"标题 : {e['title']}")
        print(f"账号 : {e['username']}")
        print(f"密码 : {e['password']}")
        if e["url"]:
            print(f"网址 : {e['url']}")
        if e["tags"]:
            print(f"标签 : {','.join(e['tags'])}")
        if e["notes"]:
            print(f"备注 : {e['notes']}")
        copy_to_clipboard(e["password"])
        print(f"（密码已复制，{CLIPBOARD_CLEAR} 秒后自动清空）")

    def cmd_add(self, args):
        title = input("标题: ").strip()
        if not title:
            print("标题不能为空")
            return
        username = input("账号: ").strip()
        pw = input("密码（留空自动生成 20 位）: ").strip()
        if not pw:
            pw = generate_password(20)
            print(f"已生成密码: {pw}")
        url = input("网址: ").strip()
        tags = [t.strip() for t in input("标签（逗号分隔）: ").split(",") if t.strip()]
        notes = input("备注: ").strip()
        e = {
            "id": self.data["next_id"],
            "title": title,
            "username": username,
            "password": pw,
            "url": url,
            "tags": tags,
            "notes": notes,
            "created": now_iso(),
            "updated": now_iso(),
            "deleted": False,
        }
        self.data["next_id"] += 1
        self.data["entries"].append(e)
        self.save()
        print(f"✅ 已添加 [{e['id']}] {title}")

    def cmd_edit(self, args):
        if not args:
            print("用法: edit <ID或标题>")
            return
        e = self.find_entry(args[0])
        if not e:
            return
        print("（直接回车保持原值）")
        v = input(f"标题 [{e['title']}]: ").strip()
        if v:
            e["title"] = v
        v = input(f"账号 [{e['username']}]: ").strip()
        if v:
            e["username"] = v
        v = input(f"密码 [{e['password']}]: ").strip()
        if v:
            e["password"] = v
        v = input(f"网址 [{e['url']}]: ").strip()
        if v:
            e["url"] = v
        v = input(f"标签 [{','.join(e['tags'])}]: ").strip()
        if v:
            e["tags"] = [t.strip() for t in v.split(",") if t.strip()]
        v = input(f"备注 [{e['notes']}]: ").strip()
        if v:
            e["notes"] = v
        e["updated"] = now_iso()
        self.save()
        print("✅ 已保存")

    def cmd_del(self, args):
        if not args:
            print("用法: del <ID>")
            return
        e = self.find_entry(args[0])
        if not e:
            return
        e["deleted"] = True
        e["updated"] = now_iso()
        self.save()
        print(f"已移入回收站: {e['title']}")

    def cmd_restore(self, args):
        if not args or not args[0].isdigit():
            print("用法: restore <ID>")
            return
        i = int(args[0])
        for e in self.data["entries"]:
            if e["id"] == i and e["deleted"]:
                e["deleted"] = False
                e["updated"] = now_iso()
                self.save()
                print(f"✅ 已恢复: {e['title']}")
                return
        print("回收站中未找到该 ID")

    def cmd_purge(self, args):
        if not args or not args[0].isdigit():
            print("用法: purge <ID>")
            return
        i = int(args[0])
        for idx, e in enumerate(self.data["entries"]):
            if e["id"] == i and e["deleted"]:
                if input(f"彻底删除 {e['title']}？不可恢复 (y/N): ").strip().lower() == "y":
                    del self.data["entries"][idx]
                    self.save()
                    print("已彻底删除")
                return
        print("回收站中未找到该 ID")

    def cmd_gen(self, args):
        length = 20
        if args:
            try:
                length = int(args[0])
            except ValueError:
                pass
        if length < 8:
            length = 8
        pw = generate_password(length)
        print(pw)
        copy_to_clipboard(pw)
        print(f"（已复制，{CLIPBOARD_CLEAR} 秒后自动清空）")

    def cmd_export(self, args):
        if len(args) < 2:
            print("用法: export csv|json <文件路径>")
            return
        fmt, path = args[0].lower(), args[1]
        if not self.confirm_password():
            return
        entries = [e for e in self.data["entries"] if not e["deleted"]]
        try:
            if fmt == "csv":
                with open(path, "w", newline="", encoding="utf-8-sig") as f:
                    w = csv.writer(f)
                    w.writerow(["标题", "账号", "密码", "网址", "标签", "备注"])
                    for e in entries:
                        w.writerow([e["title"], e["username"], e["password"],
                                    e["url"], ",".join(e["tags"]), e["notes"]])
            elif fmt == "json":
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(entries, f, ensure_ascii=False, indent=2)
            else:
                print("格式只支持 csv / json")
                return
        except OSError as e:
            print(f"写入失败: {e}")
            return
        print(f"⚠️  已导出 {len(entries)} 条明文记录到 {path}，请妥善保管并及时删除")

    def cmd_import(self, args):
        if len(args) < 2 or args[0].lower() != "csv":
            print("用法: import csv <文件路径>")
            return
        path = args[1]
        if not os.path.isfile(path):
            print("文件不存在")
            return
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
        print(f"✅ 已导入 {added} 条记录")

    def cmd_backup(self, args):
        if args:
            dst = args[0]
        else:
            bdir = os.path.join(os.path.dirname(os.path.abspath(self.vault.path)), "manual_backups")
            os.makedirs(bdir, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            dst = os.path.join(bdir, f"vault.{stamp}.dat")
        try:
            shutil.copy2(self.vault.path, dst)
        except OSError as e:
            print(f"备份失败: {e}")
            return
        print(f"✅ 已备份到 {dst}")
        print("（换电脑时：拷贝该文件 + 原U盘 + 主密码 即可使用）")

    def cmd_keybackup(self, args):
        pw = self.confirm_password()
        if not pw:
            return
        path = args[0] if args else os.path.join(
            os.path.dirname(os.path.abspath(self.vault.path)), "keybackup.vkb"
        )
        blob = make_key_backup(pw, self.keyfile_bytes)
        try:
            with open(path, "wb") as f:
                f.write(blob)
        except OSError as e:
            print(f"写入失败: {e}")
            return
        print(f"✅ 密钥备份包已保存到 {path}")
        print("请妥善保管：该文件 + 导出时使用的主密码，可在U盘丢失后恢复密钥。")

    def cmd_restore_key(self, args):
        if not args:
            print("用法: restore-key <备份包路径>")
            return
        path = args[0]
        if not os.path.isfile(path):
            print("文件不存在")
            return
        with open(path, "rb") as f:
            blob = f.read()
        pw = secure_input("请输入导出该备份包时的主密码: ")
        try:
            keyfile_bytes = open_key_backup(pw, blob)
        except VaultError as e:
            print(f"❌ {e}")
            return
        # 如果已解锁，验证是否匹配当前库
        if not self.locked:
            from crypto_layer import check_final, derive_final_key
            test = derive_final_key(self.k1, keyfile_bytes)
            if not hmac.compare_digest(check_final(test), b64d(self.header["check_final"])):
                print("⚠️  该备份包的密钥与当前库不匹配！")
                if input("仍然写入U盘？(y/N): ").strip().lower() != "y":
                    return
        mount = choose_mount()
        if not mount:
            return
        kf_path = os.path.join(mount, ".vault_key")
        if os.path.exists(kf_path):
            if input(f"{kf_path} 已存在，覆盖？(y/N): ").strip().lower() != "y":
                return
        with open(kf_path, "wb") as f:
            f.write(KEYFILE_MAGIC + keyfile_bytes)
        print(f"✅ 已恢复 keyfile 到 {kf_path}")
        if not self.locked:
            print("请执行 lock 后重新解锁验证。")

    def cmd_passwd(self, args):
        if not self.confirm_password():
            return
        new_pw = prompt_new_password()
        info = self.vault.change_password(self.keyfile_bytes, new_pw, self.data)
        self.k1 = info["k1"]
        self.salt = info["salt"]
        self.params = info["params"]
        self.final_key = info["final_key"]
        self.header = info["header"]
        print("✅ 主密码已修改。旧的密钥备份包需用导出时的旧密码才能解开。")

    def cmd_newkey(self, args):
        print("将生成新的 keyfile 并重新加密库文件，旧U盘将失效。")
        if input("确认继续？(y/N): ").strip().lower() != "y":
            return
        mount = choose_mount()
        if not mount:
            return
        kf_path = os.path.join(mount, ".vault_key")
        if os.path.exists(kf_path):
            if input(f"{kf_path} 已存在，覆盖？(y/N): ").strip().lower() != "y":
                return
        kf_file = make_keyfile_file()
        with open(kf_path, "wb") as f:
            f.write(kf_file)
        new_kf = parse_keyfile_file(kf_file)
        info = self.vault.change_keyfile(self.k1, new_kf, self.header, self.data)
        self.final_key = info["final_key"]
        self.header = info["header"]
        self.keyfile_bytes = new_kf
        self.keyfile_path = kf_path
        print(f"✅ 已更换密钥并写入 {kf_path}")
        print("旧U盘已失效，建议立即重新执行 keybackup 导出备份包。")

    def cmd_lock(self, args):
        self.lock("手动锁定")


# ---------- 独立恢复模式 ----------

def restore_key_cli(backup_path: str, mount: str | None):
    if not os.path.isfile(backup_path):
        print("备份包不存在")
        return
    with open(backup_path, "rb") as f:
        blob = f.read()
    pw = secure_input("请输入导出该备份包时的主密码: ")
    try:
        keyfile_bytes = open_key_backup(pw, blob)
    except VaultError as e:
        print(f"❌ {e}")
        return
    if not mount:
        mount = choose_mount()
    if not mount:
        return
    kf_path = os.path.join(mount, ".vault_key")
    if os.path.exists(kf_path):
        if input(f"{kf_path} 已存在，覆盖？(y/N): ").strip().lower() != "y":
            return
    with open(kf_path, "wb") as f:
        f.write(KEYFILE_MAGIC + keyfile_bytes)
    print(f"✅ 已恢复 keyfile 到 {kf_path}，现在可以正常运行程序解锁。")