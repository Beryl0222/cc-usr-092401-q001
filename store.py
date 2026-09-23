"""追加式事件账本。

所有业务事实都以不可变事件写入 JSONL 账本，重放得到当前状态。
内容删除、账号改名、授权撤回都只能追加新事件，不能覆盖或删除旧事件，
因此责任链始终可还原。
"""

import json
import os
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
                    for line in handle:
                        line = line.strip()
                        if line:
                            self.events.append(json.loads(line))

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
            self.events.append(event)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event, ensure_ascii=False) + "\n")
            for listener in list(self._listeners):
                listener(event)
            return event, False

    def replay(self):
        with self._lock:
            return list(self.events)
