#!/usr/bin/env python3
"""Exact-path app replacement. Preserves all Claude/Watch account and policy data."""
import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import plistlib
import shutil
import signal
import subprocess
import time
import uuid

APP = Path('/Applications/Claude Watch Monitor.app')
BUNDLE = 'io.local.watchpanel'
BASE = Path.home() / 'Library/Application Support/ClaudeWatch'
PLIST = Path.home() / 'Library/LaunchAgents/io.local.claudewatch.agent.plist'
JOB = 'gui/%d/io.local.claudewatch.agent' % os.getuid()
TRASH = Path.home() / '.Trash'

def run(args, check=True):
    value = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=90,
                           env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
    if check and value.returncode:
        raise RuntimeError(str(args[0]) + ': ' + value.stderr[:600])
    return value

def identity(app):
    if app.is_symlink() or not app.is_dir(): raise ValueError('应用路径不是普通目录')
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    if info.get('CFBundleIdentifier') != BUNDLE: raise ValueError('应用标识不匹配，未执行删除或权限清理')
    if info.get('CFBundleExecutable') != 'ClaudeWatchMonitor': raise ValueError('应用可执行文件不匹配')
    return info

def validate(app):
    info = identity(app)
    run(['/usr/bin/codesign', '--verify', '--deep', '--strict', app])
    resources = app / 'Contents/Resources'
    value = plistlib.loads((resources / 'BuildInfo.plist').read_bytes())
    if value.get('Architecture') != 'arm64' or value.get('ProductVersion') != info.get('CFBundleShortVersionString'):
        raise ValueError('仅接受匹配版本的 arm64 安装包')
    hashes = value.get('RuntimeHashes')
    if not isinstance(hashes, dict) or not hashes: raise ValueError('缺少运行组件校验清单')
    hashes = dict(hashes, **{'claude-watch.sh': value.get('BackendSHA256')})
    for name, expected in hashes.items():
        rel = Path(name)
        if rel.is_absolute() or '..' in rel.parts: raise ValueError('非法运行组件路径')
        path = resources / rel
        if path.is_symlink() or not path.is_file() or resources.resolve() not in path.resolve().parents:
            raise ValueError('运行组件路径无效：' + name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected: raise ValueError('运行组件校验失败：' + name)
    for path in (app/'Contents/MacOS/ClaudeWatchMonitor', resources/'watch-process-control'):
        if set(run(['/usr/bin/lipo', '-archs', path]).stdout.split()) != {'arm64'}: raise ValueError('可执行文件不是 arm64')
    return info

def no_transaction():
    for name in ('transaction.json', 'setup-transaction.json', 'update-transaction.json'):
        if (BASE/'switcher'/name).exists(): raise RuntimeError('工具操作尚在进行：' + name)
    if (BASE/'.runtime.previous').exists(): raise RuntimeError('发现尚未处理的后台升级事务')
    lock = BASE/'switcher/operation.lock'
    if lock.exists():
        with lock.open('rb') as stream: fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)

def process_rows():
    result = []
    for line in run(['/bin/ps', '-axo', 'pid=,uid=,lstart=,comm=']).stdout.splitlines():
        row = line.strip().split(None, 7)
        if len(row) == 8: result.append((int(row[0]), int(row[1]), ' '.join(row[2:7]), row[7]))
    return result

def stop_own_app():
    target = str(APP/'Contents/MacOS/ClaudeWatchMonitor')
    for row in process_rows():
        if row[1] == os.getuid() and row[3] == target and row in process_rows(): os.kill(row[0], signal.SIGTERM)
    deadline = time.monotonic() + 15
    while any(row[3] == target for row in process_rows()):
        if time.monotonic() > deadline: raise RuntimeError('Watch 界面未退出，未替换程序')
        time.sleep(.2)

def stop_own_agent():
    job = run(['/bin/launchctl', 'print', JOB], check=False)
    if job.returncode: return
    pid = next((int(l.split('=',1)[1]) for l in job.stdout.splitlines() if l.strip().startswith('pid = ')), None)
    run(['/bin/launchctl', 'bootout', JOB])
    deadline = time.monotonic() + 20
    while True:
        registered = run(['/bin/launchctl', 'print', JOB], check=False).returncode == 0
        alive = pid is not None and any(row[0] == pid for row in process_rows())
        if not registered and not alive:
            time.sleep(1)  # launchd removes the service asynchronously after bootout returns.
            if run(['/bin/launchctl', 'print', JOB], check=False).returncode != 0: return
        if time.monotonic() > deadline: raise RuntimeError('旧后台尚未完全退出，未加载新后台')
        time.sleep(.2)

def reset_accessibility():
    # Only this product. Never reset all Accessibility entries or edit TCC databases.
    run(['/usr/bin/tccutil', 'reset', 'Accessibility', BUNDLE])
    run(['/usr/bin/defaults', 'delete', BUNDLE, 'accessibilityPromptedBuild'], check=False)

def apply(source=None):
    if os.getuid() == 0: raise RuntimeError('请以当前桌面用户运行，不要用 sudo')
    if source is not None:
        source = Path(source).absolute()
        if source.resolve() == APP.resolve(): raise ValueError('安装来源必须是安装包，不能是当前安装目标')
        source_info = validate(source)
    if not APP.exists():
        if source is None: raise ValueError('未找到本产品，不清理其他权限或软件')
    else: identity(APP)
    no_transaction()
    stage = APP.parent / ('.ClaudeWatch-' + uuid.uuid4().hex + '.app')
    trash = TRASH/('ClaudeWatch-replaced-' + uuid.uuid4().hex)
    old = trash/APP.name
    had_agent = run(['/bin/launchctl','print',JOB],check=False).returncode == 0
    installed = False
    try:
        if source is not None:
            run(['/usr/bin/ditto', source, stage])
            if validate(stage) != source_info: raise RuntimeError('暂存应用版本不匹配')
        stop_own_app(); no_transaction(); stop_own_agent()
        if APP.exists():
            trash.mkdir(mode=0o700, parents=True)
            os.rename(APP, old)
            reset_accessibility()
        if source is not None:
            os.rename(stage, APP); installed = True
            run(['/bin/bash', APP/'Contents/Resources/claude-watch.sh', 'install'])
            validate(APP)
            print('已安装 ' + source_info['CFBundleShortVersionString'] + ' / build ' + source_info['CFBundleVersion'])
            print('打开新版后会请求辅助功能授权；请完成 macOS 验证。账号、代理和保护设置保留。')
        else:
            if PLIST.is_symlink(): raise ValueError('后台任务文件为符号链接，未删除')
            if PLIST.exists(): os.rename(PLIST, trash/PLIST.name)
            print('旧应用及其后台任务已移入废纸篓，辅助功能授权已清理。账号及配置数据保留。')
        print('旧应用位置：' + str(old) if old.exists() else '首次安装，无旧应用。')
    except Exception:
        if old.exists():
            stop_own_agent()
            if installed and APP.exists(): os.rename(APP, trash/'failed-new-version.app')
            if not APP.exists(): os.rename(old, APP)
            if had_agent: run(['/bin/bash', APP/'Contents/Resources/claude-watch.sh', 'install'])
        elif installed and APP.exists():
            stop_own_agent()
            trash.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.rename(APP, trash/'failed-new-version.app')
        elif had_agent and APP.exists() and run(['/bin/launchctl','print',JOB],check=False).returncode != 0:
            run(['/bin/bash', APP/'Contents/Resources/claude-watch.sh', 'install'])
        raise
    finally:
        if stage.exists(): shutil.rmtree(stage)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('install','uninstall'))
    parser.add_argument('--source', type=Path)
    args = parser.parse_args()
    if (args.action == 'install') != (args.source is not None): parser.error('安装需提供 --source；卸载不接受来源')
    apply(args.source)
