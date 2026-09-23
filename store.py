"""追加式事件账本。

所有业务事实都以不可变事件写入 JSONL 账本，重放得到当前状态。
内容删除、账号改名、授权撤回都只能追加新事件，不能覆盖或删除旧事件，
因此责任链始终可还原。

恢复约定：一行即一条完整事件。进程在写入途中退出只会留下残缺的末尾行，
加载时跳过无法解析的行（并告警），已提交的历史不受影响；写入后 flush+fsync，
保证已提交记录落盘。
"""

import json
import os
import sys
import threading
import uuid


def new_id(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class EventStore:
    """线程安全的追加式账本；path 为 None 时仅驻留内存（测试用）。"""

    def __init__(self, path=None):
        self.path = path
        self._lock = threading.RLock()
        self._listeners = []
        self.events = []
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as handle:
                    for lineno, line in enumerate(handle, start=1):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            self.events.append(json.loads(line))
                        except json.JSONDecodeError:
                            # 进程在写入途中退出会留下残缺行；跳过它以保证可恢复
                            print(f"账本 {path} 第 {lineno} 行无法解析，已跳过（疑似写入中断残留）",
                                  file=sys.stderr)

    def subscribe(self, listener):
        with self._lock:
            self._listeners.append(listener)

    def append(self, event_type, payload, event_id=None):
        """追加事件。event_id 已存在时返回既有事件（账本层幂等）。"""
        with self._lock:
            if event_id:
                for existing in self.events:
                    if existing["event_id"] == event_id:
                        return existing, True
            event = {
                "event_id": event_id or new_id("evt"),
                "seq": len(self.events) + 1,
                "type": event_type,
                "payload": payload,
            }
            if self.path:
                # 先落盘再入内存：写盘失败时内存投影不产生幽灵事件
                line = json.dumps(event, ensure_ascii=False) + "\n"
                with open(self.path, "a", encoding="utf-8") as handle:
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())
            self.events.append(event)
            for listener in list(self._listeners):
                listener(event)
            return event, False

    def replay(self):
        with self._lock:
            return list(self.events)
