"""回调链可靠性测试：原子事务、故障注入恢复、并发单胜者、重启一致性。

覆盖昨夜事故的每一种形态：
- 进程在落账前/写盘一半/提交后被杀，重启后账本要么整组生效要么整组缺席；
- 完全相同的重传返回首次结果，同标识异内容 409 且错误不泄露敏感正文；
- 同标识并发只有一个胜者，异内容并发一胜一冲突、败者零写入；
- 合并/关闭事件的迟到回调归入责任链主事件，不重开旧事件；
- 重启后接口响应与最终账本逐字节稳定。
"""

import json
import os
import tempfile
import threading
import unittest
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from app import AppError, SafeguardingApp
from service import build_handler
from store import EventStore, ProcessCrash

AGENT = {"name": "代理人小林", "role": "当事人代理"}
OFFICER = {"name": "保护专员阿岚", "role": "俱乐部保护专员"}

ABUSE_TEXT = "这人就该被网暴到退役，全家都不是好东西"
CONTENT_URL = "https://video.example/comment/55"
ACCOUNT_KEY = "dy_hater_9"
SECRET_URL = "https://video.example/comment/55"
NAME_BEFORE = "改名前的账号名"
NAME_AFTER = "改名后的账号名"
RECEIPT_ID = "DY-8840217"


def abuse_report(**overrides):
    payload = {
        "victim_code": "ATH-009",
        "platform": "douyin",
        "content_url": CONTENT_URL,
        "raw_excerpt": ABUSE_TEXT,
        "severity": "abuse",
        "linked_accounts": [
            {"platform": "douyin", "account_key": ACCOUNT_KEY,
             "url": "https://video.example/u/9", "display_name": "辱骂账号"}
        ],
        "授权范围": ["report", "evidence_storage", "platform_complaint"],
    }
    payload.update(overrides)
    return payload


def callback(payload_id="CB-001", incident_id=None, status="removed",
             account_name=NAME_BEFORE, receipt_id=RECEIPT_ID, url=CONTENT_URL,
             reported_at="2026-09-18T21:03:00+08:00"):
    body = {
        "callback_id": payload_id,
        "receipt": {
            "receipt_id": receipt_id, "platform": "douyin",
            "status": status, "reported_at": reported_at, "content_url": url,
        },
        "account": {"platform": "douyin", "account_key": ACCOUNT_KEY,
                    "display_name": account_name},
    }
    if incident_id is not None:
        body["incident_id"] = incident_id
    return body


def event_counts(app):
    return Counter(e["type"] for e in app.store.replay())


def open_shop(path=None):
    app = SafeguardingApp(store_path=path)
    incident_id = app.submit_report(abuse_report(), AGENT)["incident_id"]
    return app, incident_id


# ---------------------------------------------------------------- 账本事务
class LedgerTransactionTest(unittest.TestCase):
    def test_batch_is_one_durable_line_and_expands_on_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.jsonl")
            store = EventStore(path)
            store.append_batch([
                ("receipt_recorded", {"receipt_id": "R1", "at": "t"}),
                ("content_state_changed", {"evidence_id": "E1", "at": "t"}),
                ("callback_processed", {"callback_id": "CB1", "at": "t"}),
            ])
            with open(path, "r", encoding="utf-8") as handle:
                lines = [line for line in handle.read().splitlines() if line.strip()]
            self.assertEqual(len(lines), 1)  # 整组只占一行：原子提交单元
            record = json.loads(lines[0])
            self.assertIn("txn_id", record)
            self.assertEqual([e["type"] for e in record["events"]],
                             ["receipt_recorded", "content_state_changed",
                              "callback_processed"])

            reloaded = EventStore(path)
            types = [e["type"] for e in reloaded.replay()]
            self.assertEqual(types, ["receipt_recorded", "content_state_changed",
                                     "callback_processed"])
            txns = {e["in_txn"] for e in reloaded.replay()}
            self.assertEqual(len(txns), 1)  # 三者同属一个事务

    def test_batch_rolls_back_when_block_raises(self):
        store = EventStore()
        with self.assertRaises(RuntimeError):
            with store.transaction() as txn:
                txn.append("receipt_recorded", {"receipt_id": "R1"})
                txn.append("callback_processed", {"callback_id": "CB1"})
                raise RuntimeError("business validation failed after staging")
        self.assertEqual(store.replay(), [])

    def test_nested_lock_inside_critical_section(self):
        store = EventStore()
        with store.lock:  # 业务临界区已持锁
            events = store.append_batch([("receipt_recorded", {"x": 1})])
        self.assertEqual(len(events), 1)

    def test_legacy_single_event_line_still_replays(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.jsonl")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps({
                    "event_id": "evt_legacy", "seq": 1,
                    "type": "notification_sent",
                    "payload": {"notif_id": "n1"}}, ensure_ascii=False) + "\n")
            reloaded = EventStore(path)
            self.assertEqual(reloaded.replay()[0]["type"], "notification_sent")


# ----------------------------------------------------------- 回调事务原子性
class AtomicCallbackTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "events.jsonl")
        self.app, self.incident_id = open_shop(self.path)
        self.baseline = event_counts(self.app)

    def tearDown(self):
        self.tmp.cleanup()

    def _assert_callback_absent(self, app):
        counts = event_counts(app)
        for etype in ("receipt_recorded", "content_state_changed",
                      "account_renamed", "callback_processed"):
            self.assertEqual(counts[etype], self.baseline[etype],
                             f"崩溃后不应残留 {etype}")
        self.assertNotIn("CB-001", app.callbacks)
        self.assertEqual(len(app.incidents), 1)
        self.assertEqual(app.list_notifications(), [])

    def test_pre_commit_crash_leaves_zero_effects(self):
        self.app.store.inject_crash("pre_commit")
        with self.assertRaises(ProcessCrash):
            self.app.platform_callback(callback(incident_id=self.incident_id))
        self._assert_callback_absent(self.app)

        # 进程恢复（同账本重新打开）后重放：整组一次性生效，各事实只有一份
        recovered = SafeguardingApp(store_path=self.path)
        result = recovered.platform_callback(callback(incident_id=self.incident_id))
        self.assertFalse(result["duplicate"])
        self._assert_exactly_one_callback_effect(recovered)

    def test_torn_tail_is_quarantined_and_callback_can_replay(self):
        self.app.store.inject_crash("torn")
        with self.assertRaises(ProcessCrash):
            self.app.platform_callback(callback(incident_id=self.incident_id))
        # 磁盘上留有写了一半的事务行
        with open(self.path, "r", encoding="utf-8") as handle:
            tail = handle.readlines()[-1]
        with self.assertRaises(json.JSONDecodeError):
            json.loads(tail)

        # 新进程打开账本：撕裂行被封存，账本仍可用
        recovered = SafeguardingApp(store_path=self.path)
        self._assert_callback_absent(recovered)
        self.assertTrue(os.path.exists(recovered.store.quarantine_path))
        result = recovered.platform_callback(callback(incident_id=self.incident_id))
        self.assertFalse(result["duplicate"])
        self._assert_exactly_one_callback_effect(recovered)

        # 再重启一次：封存只做一次，账本不增长、不重复
        events_after_first_recovery = len(EventStore(self.path).replay())
        again = EventStore(self.path)
        self.assertEqual(len(again.replay()), events_after_first_recovery)

    def test_post_commit_crash_loses_nothing(self):
        self.app.store.inject_crash("post_commit")
        with self.assertRaises(ProcessCrash):
            self.app.platform_callback(callback(incident_id=self.incident_id))
        recovered = SafeguardingApp(store_path=self.path)
        self._assert_exactly_one_callback_effect(recovered)
        again = recovered.platform_callback(callback(incident_id=self.incident_id))
        self.assertTrue(again["duplicate"])  # 提交结果不丢，重传取首次结果

    def test_effects_share_one_transaction_in_durable_ledger(self):
        self.app.platform_callback(callback(incident_id=self.incident_id))
        with open(self.path, "r", encoding="utf-8") as handle:
            records = [json.loads(line) for line in handle if line.strip()]
        txn_records = [r for r in records if "events" in r]
        cb_txn = next(r for r in txn_records
                      if any(e["type"] == "callback_processed" for e in r["events"]))
        types = {e["type"] for e in cb_txn["events"]}
        # 回执、内容状态、账号关系、已处理标记在同一事务行内同生共死
        self.assertEqual(types, {
            "receipt_recorded", "content_state_changed",
            "account_renamed", "callback_processed"})

    def _assert_exactly_one_callback_effect(self, app):
        counts = event_counts(app)
        self.assertEqual(counts["receipt_recorded"] - self.baseline["receipt_recorded"], 1)
        self.assertEqual(counts["content_state_changed"] - self.baseline["content_state_changed"], 1)
        self.assertEqual(counts["account_renamed"] - self.baseline["account_renamed"], 1)
        self.assertEqual(counts["callback_processed"] - self.baseline["callback_processed"], 1)
        digest = app.incident_digest(self.incident_id)
        self.assertEqual(len(digest["证据依据"]["platform_receipts"]), 1)
        self.assertEqual([e["state"] for e in digest["证据依据"]["evidence"]], ["deleted"])
        account = digest["证据依据"]["linked_accounts"][0]
        self.assertEqual(account["display_name"], NAME_BEFORE)
        self.assertEqual(len(account["name_history"]), 2)
        self.assertEqual(len(app.incidents), 1)
        self.assertEqual(app.list_notifications(), [])


# --------------------------------------------------------------- 指纹与冲突
class FingerprintConflictTest(unittest.TestCase):
    def setUp(self):
        self.app, self.incident_id = open_shop()

    def test_exact_retry_returns_first_result_every_time(self):
        first = self.app.platform_callback(callback(incident_id=self.incident_id))
        second = self.app.platform_callback(callback(incident_id=self.incident_id))
        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])
        self.assertEqual({k: v for k, v in second.items() if k != "duplicate"},
                         {k: v for k, v in first.items() if k != "duplicate"})
        third = self.app.platform_callback(callback(incident_id=self.incident_id))
        self.assertEqual(third, second)
        # 不重复挂接、不重复通知、不产生第二案件
        digest = self.app.incident_digest(self.incident_id)
        self.assertEqual(len(digest["证据依据"]["platform_receipts"]), 1)
        self.assertEqual(self.app.incident_digest(self.incident_id)
                         ["证据依据"]["linked_accounts"][0]["display_name"], NAME_BEFORE)
        self.assertEqual(event_counts(self.app)["callback_processed"], 1)

    def test_metadata_only_refresh_is_still_same_retry(self):
        self.app.platform_callback(callback(incident_id=self.incident_id))
        refreshed = callback(incident_id=self.incident_id,
                             reported_at="2026-09-18T22:10:00+08:00")
        self.assertTrue(self.app.platform_callback(refreshed)["duplicate"])

    def test_same_id_different_content_conflicts_and_leaks_nothing(self):
        self.app.platform_callback(callback(incident_id=self.incident_id))
        events_before = len(self.app.store.replay())

        for tampered in (
            callback(incident_id=self.incident_id, status="accepted"),
            callback(incident_id=self.incident_id, account_name=NAME_AFTER),
            callback(incident_id=self.incident_id, receipt_id="DY-9999999"),
        ):
            with self.assertRaises(AppError) as ctx:
                self.app.platform_callback(tampered)
            self.assertEqual(ctx.exception.status, 409)
            message = str(ctx.exception)
            # 明确是冲突，但不回显受控引用、账号名、回执号等敏感定位信息
            self.assertIn("冲突", message)
            self.assertNotIn(SECRET_URL, message)
            self.assertNotIn(NAME_BEFORE, message)
            self.assertNotIn(NAME_AFTER, message)
            self.assertNotIn(RECEIPT_ID, message)
            self.assertNotIn(ABUSE_TEXT, message)
            # 败者零写入
            self.assertEqual(len(self.app.store.replay()), events_before)

        # 首次结果原样保留：仍是 removed + 改名前
        digest = self.app.incident_digest(self.incident_id)
        self.assertEqual(digest["证据依据"]["platform_receipts"][0]["status"], "removed")
        self.assertEqual(digest["证据依据"]["linked_accounts"][0]["display_name"], NAME_BEFORE)
        self.assertEqual([e["state"] for e in digest["证据依据"]["evidence"]], ["deleted"])
        self.assertEqual(event_counts(self.app)["callback_processed"], 1)


# ------------------------------------------------------------------- 并发
class ConcurrentCallbackTest(unittest.TestCase):
    def setUp(self):
        self.app, self.incident_id = open_shop()

    def test_identical_concurrent_callbacks_have_single_winner(self):
        body = callback(incident_id=self.incident_id)
        winners, duplicates, errors = self._race(body, 8)
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(duplicates), 7)
        self.assertEqual(errors, [])
        counts = event_counts(self.app)
        self.assertEqual(counts["callback_processed"], 1)
        self.assertEqual(counts["receipt_recorded"], 1)
        self.assertEqual(counts["content_state_changed"], 1)
        self.assertEqual(counts["account_renamed"], 1)
        self.assertEqual(len(self.app.incidents), 1)
        self.assertEqual(self.app.list_notifications(), [])

    def test_conflicting_concurrent_callbacks_one_wins_one_conflicts(self):
        def race_two(callback_id, round_no):
            # 每轮独立回执号，避免跨轮语义交织，只验证本轮竞争的结构性结果
            version_a = callback(payload_id=callback_id, incident_id=self.incident_id,
                                 status="removed", account_name=NAME_BEFORE,
                                 receipt_id=f"DY-RACE-{round_no}-A")
            version_b = callback(payload_id=callback_id, incident_id=self.incident_id,
                                 status="accepted", account_name=NAME_AFTER,
                                 receipt_id=f"DY-RACE-{round_no}-B")
            barrier = threading.Barrier(2)

            def call(body):
                barrier.wait()
                try:
                    return ("ok", self.app.platform_callback(body))
                except AppError as error:
                    return ("conflict", error.status)

            with ThreadPoolExecutor(max_workers=2) as pool:
                futs = [pool.submit(call, version_a), pool.submit(call, version_b)]
                return [f.result() for f in futs]

        rounds = 10
        # 高竞争下重复多轮，性质必须稳定：每轮恰一个成功、一个 409、败者零写入
        for round_no in range(rounds):
            kinds = [r[0] for r in race_two(f"CB-RACE-{round_no}", round_no)]
            self.assertEqual(sorted(kinds), ["conflict", "ok"])

        counts = event_counts(self.app)
        self.assertEqual(counts["callback_processed"], rounds)
        self.assertEqual(counts["receipt_recorded"], rounds)
        # 投影可正常读取、无半状态：每个回执只出现一次，证据状态始终合法
        digest = self.app.incident_digest(self.incident_id)
        receipts = digest["证据依据"]["platform_receipts"]
        self.assertEqual(len(receipts), rounds)
        self.assertEqual(len({r["receipt_id"] for r in receipts}), rounds)
        self.assertTrue(all(e["state"] in ("online", "deleted")
                            for e in digest["证据依据"]["evidence"]))
        self.assertEqual(len(self.app.incidents), 1)
        self.assertEqual(self.app.list_notifications(), [])

    def test_distinct_callback_ids_concurrently_all_succeed(self):
        bodies = [callback(payload_id=f"CB-{i}", incident_id=self.incident_id,
                           receipt_id=f"DY-{i}", account_name=None)
                  for i in range(4)]
        # account_name=None 时账号已存在且无新名字，不产生挂接；聚焦不同键不互斥
        winners, duplicates, errors = self._race_many(bodies)
        self.assertEqual(errors, [])
        self.assertEqual(len(winners), 4)
        self.assertEqual(duplicates, [])

    def _race(self, body, n):
        barrier = threading.Barrier(n)

        def call():
            barrier.wait()
            try:
                result = self.app.platform_callback(body)
                return "winner" if not result["duplicate"] else "duplicate"
            except AppError as error:
                return ("error", error.status)

        with ThreadPoolExecutor(max_workers=n) as pool:
            outcomes = list(pool.map(lambda _: call(), range(n)))
        winners = [o for o in outcomes if o == "winner"]
        duplicates = [o for o in outcomes if o == "duplicate"]
        errors = [o for o in outcomes if isinstance(o, tuple)]
        return winners, duplicates, errors

    def _race_many(self, bodies):
        barrier = threading.Barrier(len(bodies))

        def call(body):
            barrier.wait()
            try:
                result = self.app.platform_callback(body)
                return "winner" if not result["duplicate"] else "duplicate"
            except AppError as error:
                return ("error", error.status)

        with ThreadPoolExecutor(max_workers=len(bodies)) as pool:
            outcomes = list(pool.map(call, bodies))
        winners = [o for o in outcomes if o == "winner"]
        duplicates = [o for o in outcomes if o == "duplicate"]
        errors = [o for o in outcomes if isinstance(o, tuple)]
        return winners, duplicates, errors


# ------------------------------------------------------- 合并/关闭责任线路由
class ChainRoutingTest(unittest.TestCase):
    def _merged_pair(self):
        app = SafeguardingApp()
        first = app.submit_report(abuse_report(), AGENT)["incident_id"]
        second = app.submit_report(abuse_report(
            content_url="https://video.example/comment/55?mirror=1"), AGENT)["incident_id"]
        suggestion = app.list_suggestions()[0]["suggestion_id"]
        app.resolve_suggestion(suggestion, "accept", OFFICER, target_incident=first)
        return app, first, second

    def test_late_callback_on_merged_incident_routes_to_survivor(self):
        app, first, second = self._merged_pair()
        late = callback(payload_id="CB-LATE", incident_id=second,
                        url="https://video.example/comment/55?mirror=1")
        result = app.platform_callback(late)

        self.assertFalse(result["duplicate"])
        self.assertEqual(result["incident_id"], first)   # 归到责任链主事件
        self.assertEqual(result["routed_from"], second)
        # 旧事件没有被重新打开
        self.assertEqual(app.incidents[second]["merged_into"], first)
        self.assertIsNone(app.incidents[second]["closed_at"])
        with self.assertRaises(AppError) as ctx:
            app.add_evidence(second, {"content_ref": "u"}, AGENT)
        self.assertEqual(ctx.exception.status, 409)
        # 主事件责任链包含迟到回执，且镜像证据（在被吸收事件上）被标记删除
        survivor = app.incident_digest(first)
        chain_types = [c["type"] for c in survivor["责任链"]]
        self.assertIn("receipt_recorded", chain_types)
        self.assertIn("content_state_changed", chain_types)
        chain_payloads = [c["payload"] for c in survivor["责任链"]
                          if c["type"] == "content_state_changed"]
        self.assertTrue(any(p["incident_id"] == second for p in chain_payloads))
        self.assertEqual(len(app.incidents), 2)  # 没有第二案件（合并仍是两件）
        self.assertEqual(app.list_notifications(), [])

        # 完全相同的迟到回调重传：仍返回首次路由结果
        replay = app.platform_callback(late)
        self.assertTrue(replay["duplicate"])
        self.assertEqual(replay["incident_id"], first)
        self.assertEqual(replay["routed_from"], second)

    def test_late_callback_after_close_appends_but_never_reopens(self):
        app, incident_id = open_shop()
        app.close_incident(incident_id, "保护到位，关闭", OFFICER)
        closed_at = app.incidents[incident_id]["closed_at"]

        late = callback(payload_id="CB-CLOSED", incident_id=incident_id)
        result = app.platform_callback(late)
        self.assertFalse(result["duplicate"])
        self.assertEqual(result["incident_id"], incident_id)
        self.assertNotIn("routed_from", result)
        # 关闭状态不被迟到事实推翻
        digest = app.incident_digest(incident_id)
        self.assertEqual(digest["status"], "已关闭")
        self.assertEqual(digest["closed_at"], closed_at)
        chain_types = [c["type"] for c in digest["责任链"]]
        self.assertIn("receipt_recorded", chain_types)
        self.assertIn("content_state_changed", chain_types)
        # 关闭事件仍不可再被业务写接口变更
        with self.assertRaises(AppError):
            app.add_evidence(incident_id, {"content_ref": "u"}, AGENT)

    def test_unknown_merged_reference_resolves_through_chain(self):
        app, first, second = self._merged_pair()
        # 不带 incident_id，仅凭被吸收事件的内容 URL 定位，同样路由到主事件
        late = callback(payload_id="CB-URL",
                        url="https://video.example/comment/55?mirror=1")
        result = app.platform_callback(late)
        self.assertEqual(result["incident_id"], first)
        self.assertEqual(result["routed_from"], second)


# ------------------------------------------------------------- 重启一致性
class RestartConsistencyTest(unittest.TestCase):
    def test_responses_and_ledger_are_stable_across_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.jsonl")
            app, incident_id = open_shop(path)
            first_cb = callback(incident_id=incident_id)
            first_resp = app.platform_callback(first_cb)
            second_cb = callback(payload_id="CB-002", incident_id=incident_id,
                                 account_name=NAME_AFTER, receipt_id="DY-200")
            second_resp = app.platform_callback(second_cb)
            snapshot = self._snapshot(app)

            # 模拟重启：新进程重放追加式账本，再重放全部回调
            reloaded = SafeguardingApp(store_path=path)
            replay_first = reloaded.platform_callback(first_cb)
            replay_second = reloaded.platform_callback(second_cb)
            self.assertTrue(replay_first["duplicate"])
            self.assertTrue(replay_second["duplicate"])
            self.assertEqual({k: v for k, v in replay_first.items() if k != "duplicate"},
                             {k: v for k, v in first_resp.items() if k != "duplicate"})
            self.assertEqual({k: v for k, v in replay_second.items() if k != "duplicate"},
                             {k: v for k, v in second_resp.items() if k != "duplicate"})
            self.assertEqual(self._snapshot(reloaded), snapshot)

            # 再来一次重启，账本与响应依旧
            reloaded_twice = SafeguardingApp(store_path=path)
            self.assertEqual(self._snapshot(reloaded_twice), snapshot)
            self.assertTrue(
                reloaded_twice.platform_callback(first_cb)["duplicate"])

    def _snapshot(self, app):
        digest = app.incident_digest(
            next(iter(app.incidents)))
        return {
            "counts": json.loads(json.dumps(event_counts(app))),
            "receipts": digest["证据依据"]["platform_receipts"],
            "evidence_states": [(e["content_ref"], e["state"])
                                for e in digest["证据依据"]["evidence"]],
            "accounts": [(a["account_key"], a["display_name"],
                          [h["name"] for h in a["name_history"]])
                         for a in digest["证据依据"]["linked_accounts"]],
            "callbacks": sorted(app.callbacks.keys()),
            "incidents": sorted(app.incidents.keys()),
        }


# ---------------------------------------------------------------- HTTP 并发
class HttpReliabilityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = os.path.join(cls.tmp.name, "events.jsonl")
        cls.app = SafeguardingApp(store_path=cls.path)
        cls.incident_id = cls.app.submit_report(abuse_report(), AGENT)["incident_id"]
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.app))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.tmp.cleanup()

    def _post(self, body):
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        request = Request(f"{self.base_url}/callbacks/platform", data=data,
                          method="POST", headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)

    def test_parallel_identical_callbacks_single_winner_over_http(self):
        body = callback(incident_id=self.incident_id, receipt_id="DY-HTTP-1")
        barrier = threading.Barrier(6)

        def call():
            barrier.wait()
            return self._post(body)

        with ThreadPoolExecutor(max_workers=6) as pool:
            outcomes = list(pool.map(lambda _: call(), range(6)))
        statuses = Counter(code for code, _ in outcomes)
        self.assertEqual(statuses[200], 6)
        winners = [body for code, body in outcomes if not body["duplicate"]]
        self.assertEqual(len(winners), 1)

    def test_conflict_response_over_http_does_not_leak(self):
        body = callback(payload_id="CB-HTTP-CONFLICT",
                        incident_id=self.incident_id, receipt_id="DY-HTTP-2")
        code, _ = self._post(body)
        self.assertEqual(code, 200)
        code, error_body = self._post(callback(
            payload_id="CB-HTTP-CONFLICT", incident_id=self.incident_id,
            receipt_id="DY-HTTP-2", status="accepted"))
        self.assertEqual(code, 409)
        message = error_body["error"]
        self.assertIn("冲突", message)
        self.assertNotIn(CONTENT_URL, message)
        self.assertNotIn(NAME_BEFORE, message)
        self.assertNotIn("DY-HTTP-2", message)


if __name__ == "__main__":
    unittest.main()
