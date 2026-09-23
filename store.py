"""追加式事件账本。

所有业务事实都以不可变事件写入 JSONL 账本，重放得到当前状态。
内容删除、账号改名、授权撤回都只能追加新事件，不能覆盖或删除旧事件，
因此责任链始终可还原。

原子性
------
一个业务动作（如平台回调）涉及的多个事实必须"要么共同生效、要么都不生效"。
为此多条事件组成一个事务：提交时只向账本追加**一行**事务记录
（``{"txn_id", "events": [...]}``），配合 flush+fsync，进程在任一写入点
中断后，磁盘上要么有完整的事务行、要么没有，不会出现"半个回调"。

重放时事务记录被展开为其中的事件（``in_txn`` 标记其归属），投影层无感知。
若最后一行因崩溃被撕裂（写了一半），该行被封存到 ``.quarantine`` 旁路文件，
绝不半行入账——系统宁可重做该动作（由幂等索引保证安全），也不接受半成品状态。

并发
----
``store.lock`` 是可重入锁（RLock）：业务层可以把"查重 → 路由 → 构造 → 提交"
整个临界区包进同一把锁，事务提交（嵌套获取）互不阻塞，保证同标识并发请求
只有一个胜者。
"""

import json
import os
import threading
import uuid


def new_id(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class ProcessCrash(RuntimeError):
    """测试用故障注入：模拟进程在指定写入点被杀掉。

    - ``pre_commit``：业务校验与事件构造完毕、任何落盘之前被杀（无副作用）；
    - ``torn``：事务行写到一半被杀（制造撕裂尾部，验证封存与重做恢复）；
    - ``post_commit``：事务已 fsync 落盘、调用方尚未继续时被杀（提交结果不丢）。
    """

    def __init__(self, point):
        super().__init__(f"injected crash at {point}")
        self.point = point


class EventStore:
    """线程安全的追加式账本；path 为 None 时仅驻留内存（测试用）。"""

    def __init__(self, path=None):
        self.path = path
        self.lock = threading.RLock()
        self._listeners = []
        self.events = []
        # 崩溃注入：{point: 剩余触发次数}，仅测试使用
        self.crash_injections = {}
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            self._load()

    # ------------------------------------------------------------------ 恢复
    def _load(self):
        """从磁盘重放；撕裂的尾部行封存到旁路文件，不污染账本。"""
        if not self.path or not os.path.exists(self.path):
            return
        quarantined = False
        with open(self.path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
        good_lines = []
        for line in lines:
            if not line.strip():
                good_lines.append(line)
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # 撕裂行只可能出现在尾部（所有写入都在同一把追加锁下串行）；
                # 截断好行、封存坏行后等待动作以幂等方式重做。
                quarantined = True
                break
            good_lines.append(line)
            self._ingest_record(record)
        if quarantined and len(good_lines) != len(lines):
            bad = lines[len(good_lines):]
            with open(self.quarantine_path, "a", encoding="utf-8") as side:
                for line in bad:
                    side.write(f"# quarantined torn line\n{line}")
            with open(self.path, "w", encoding="utf-8") as handle:
                handle.writelines(good_lines)
                handle.flush()
                os.fsync(handle.fileno())

    @property
    def quarantine_path(self):
        return self.path + ".quarantine"

    def _ingest_record(self, record):
        """把一行磁盘记录入账本内存视图：事务记录展开为多个事件。"""
        if isinstance(record, dict) and "events" in record and "txn_id" in record:
            for index, item in enumerate(record["events"]):
                self.events.append(self._expanded(item, record["txn_id"], index))
        else:
            # 兼容历史账本中的单事件行
            self.events.append(record)

    def _expanded(self, item, txn_id, index):
        event = {
            "event_id": item.get("event_id") or new_id("evt"),
            "type": item["type"],
            "seq": len(self.events) + 1,
            "payload": item["payload"],
            "in_txn": txn_id,
        }
        if index == 0:
            event["txn_lead"] = True
        return event

    # ------------------------------------------------------------------ 订阅
    def subscribe(self, listener):
        with self.lock:
            self._listeners.append(listener)

    # ------------------------------------------------------------------ 写入
    def transaction(self):
        """返回事务上下文管理器：with store.transaction() as txn: txn.append(...).

        进入即持有账本锁（可重入），块内事件只缓冲不落盘；块正常退出时整组
        以一行原子提交。块内抛异常（含注入的 pre_commit 崩溃）则不写入任何事件。
        """
        return _Transaction(self)

    def append(self, event_type, payload):
        """追加单条事件（自身构成一个事务）。"""
        with self.transaction() as txn:
            txn.append(event_type, payload)
        return txn.committed_events[0]

    def append_batch(self, items):
        """整组事件作为一个事务原子提交；返回展开后的事件列表。

        items 为 (event_type, payload) 序列。可在已持有 ``store.lock`` 的
        临界区内调用（锁可重入）。
        """
        with self.transaction() as txn:
            for event_type, payload in items:
                txn.append(event_type, payload)
        return list(txn.committed_events)

    def inject_crash(self, point, times=1):
        """配置故障注入：下一次（或下 times 次）提交到达 point 时崩溃。"""
        self.crash_injections[point] = times

    def _maybe_crash(self, point):
        remaining = self.crash_injections.get(point, 0)
        if remaining > 0:
            self.crash_injections[point] = remaining - 1
            raise ProcessCrash(point)

    def replay(self):
        with self.lock:
            return list(self.events)


class _Transaction:
    """一组事件的原子提交单元。"""

    def __init__(self, store):
        self._store = store
        self._items = []
        self._rolled_back = False
        self.committed_events = None

    def append(self, event_type, payload):
        self._items.append({
            "event_id": new_id("evt"),
            "type": event_type,
            "payload": payload,
        })

    def __enter__(self):
        self._store.lock.acquire()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is not None:
                # 业务异常或 pre_commit 注入崩溃：缓冲整体丢弃，磁盘零改动
                self._rolled_back = True
                return False
            self._commit()
            return False
        finally:
            self._store.lock.release()

    def _commit(self):
        store = self._store
        store._maybe_crash("pre_commit")
        txn_id = new_id("txn")
        record = {"txn_id": txn_id, "events": self._items}
        line = json.dumps(record, ensure_ascii=False)
        expanded = [store._expanded(item, txn_id, index)
                    for index, item in enumerate(self._items)]

        if store.path:
            # torn 注入：只落半个事务行，模拟写盘途中被杀。
            # 真实崩溃同样可能留下部分字节，重放侧按撕裂行封存，二者恢复路径一致。
            if store.crash_injections.get("torn", 0) > 0:
                store.crash_injections["torn"] -= 1
                partial = line[: max(1, len(line) // 2)]
                with open(store.path, "a", encoding="utf-8") as handle:
                    handle.write(partial)
                    handle.flush()
                    os.fsync(handle.fileno())
                raise ProcessCrash("torn")

            with open(store.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        elif store.crash_injections.get("torn", 0) > 0:
            # 内存账本：模拟同一时刻的进程死亡（没有半成品字节需要封存）
            store.crash_injections["torn"] -= 1
            raise ProcessCrash("torn")

        store.events.extend(expanded)
        self.committed_events = expanded
        for event in expanded:
            for listener in list(store._listeners):
                listener(event)

        # post_commit：数据已 fsync，进程此刻被杀，重启后重放必须得到相同结果
        store._maybe_crash("post_commit")
