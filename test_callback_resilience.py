"""回调链韧性测试：原子提交、幂等重传、内容冲突、故障注入、并发与重启恢复。

覆盖事故复盘提出的全部要求：
- 回执、内容状态、账号关系与已处理标记合为一条账本记录，要么共同生效要么都不生效；
- 完全相同的重传返回首次结果；同标识异内容明确冲突（409）且不泄露敏感正文；
- 并发到达的同一 callback_id 只有一个胜者；
- 进程在任一写入点中断后都可从追加式账本恢复，不重复通知、不重复挂接、不产生第二案件；
- 合并或关闭事件收到迟到回调归到正确的责任链，不把旧事件重新打开；
- 重启重放后最终账本与接口响应一致。
"""

import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from app import AppError, SafeguardingApp
from service import build_handler

AGENT = {"name": "代理人小林", "role": "当事人代理"}
OFFICER = {"name": "保护专员阿岚", "role": "俱乐部保护专员"}
DUTY = {"name": "值班主管老周", "role": "俱乐部值班主管"}


def abuse_report(**overrides):
    payload = {
        "victim_code": "ATH-009",
        "platform": "douyin",
        "content_url": "https://video.example/comment/55",
        "raw_excerpt": "这人就该被网暴到退役，全家都不是好东西",
        "severity": "abuse",
        "linked_accounts": [
            {"platform": "douyin", "account_key": "dy_hater_9",
             "url": "https://video.example/u/9", "display_name": "辱骂账号"}
        ],
        "授权范围": ["report", "evidence_storage", "platform_complaint"],
    }
    payload.update(overrides)
    return payload


def threat_report(**overrides):
    payload = {
        "victim_code": "ATH-007",
        "platform": "weibo",
        "content_url": "https://weibo.example/comment/90210",
        "raw_excerpt": "你在19号更衣室门口等着，今晚别想走着出去",
        "severity": "direct_threat",
        "linked_accounts": [
            {"platform": "weibo", "account_key": "u_threat_77",
             "url": "https://weibo.example/u/77", "display_name": "黑哨敢死队"}
        ],
        "授权范围": ["report", "evidence_storage", "platform_complaint",
                  "police_report", "public_statement"],
    }
    payload.update(overrides)
    return payload


def removal_callback(incident_id, callback_id="CB-R1", name="改名后的账号名",
                     content_url="https://video.example/comment/55"):
    """平台处置回执回调：内容已删除 + 账号更名。"""
    return {
        "callback_id": callback_id,
        "incident_id": incident_id,
        "receipt": {
            "receipt_id": "DY-8840217", "platform": "douyin",
            "status": "removed",
            "reported_at": "2026-09-18T21:03:00+08:00",
            "content_url": content_url,
        },
        "account": {"platform": "douyin", "account_key": "dy_hater_9",
                    "display_name": name},
    }


def without_duplicate_flag(body):
    return {k: v for k, v in body.items() if k != "duplicate"}


class CallbackAtomicityTest(unittest.TestCase):
    """原子提交、幂等重传与内容冲突（内存账本）。"""

    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]

    def callback_records(self):
        return [e for e in self.app.store.replay() if e["type"] == "callback_processed"]

    def test_single_record_commits_all_effects_atomically(self):
        result = self.app.platform_callback(removal_callback(self.incident_id))
        self.assertFalse(result["duplicate"])
        self.assertEqual(result["attached"], ["receipt", "content_deleted", "account_renamed"])
        # 回执、内容状态、账号关系与已处理标记合为一条账本记录
        records = self.callback_records()
        self.assertEqual(len(records), 1)
        payload = records[0]["payload"]
        self.assertEqual(payload["callback_id"], "CB-R1")
        self.assertEqual(payload["incident_id"], self.incident_id)
        self.assertTrue(payload["fingerprint"])
        self.assertEqual([t for t, _ in payload["effects"]],
                         ["receipt_recorded", "content_state_changed", "account_renamed"])
        # 投影同步生效，且回调不产生任何通知
        digest = self.app.incident_digest(self.incident_id)
        self.assertEqual(len(digest["证据依据"]["platform_receipts"]), 1)
        self.assertEqual(digest["证据依据"]["evidence"][0]["state"], "deleted")
        self.assertEqual(digest["证据依据"]["linked_accounts"][0]["display_name"], "改名后的账号名")
        self.assertEqual(self.app.list_notifications(), [])

    def test_identical_retransmission_returns_first_result(self):
        first = self.app.platform_callback(removal_callback(self.incident_id))
        again = self.app.platform_callback(removal_callback(self.incident_id))
        self.assertTrue(again["duplicate"])
        self.assertEqual(without_duplicate_flag(again), without_duplicate_flag(first))
        self.assertEqual(len(self.callback_records()), 1)  # 没有第二次落账
        digest = self.app.incident_digest(self.incident_id)
        self.assertEqual(len(digest["证据依据"]["platform_receipts"]), 1)
        history = digest["证据依据"]["linked_accounts"][0]["name_history"]
        self.assertEqual([h["name"] for h in history], ["辱骂账号", "改名后的账号名"])

    def test_conflicting_content_rejected_without_leaking(self):
        self.app.platform_callback(removal_callback(self.incident_id))
        hostile = removal_callback(self.incident_id)
        hostile["account"]["display_name"] = "伪造的账号名"
        hostile["receipt"]["receipt_id"] = "DY-FORGED"
        with self.assertRaises(AppError) as ctx:
            self.app.platform_callback(hostile)
        self.assertEqual(ctx.exception.status, 409)
        message = str(ctx.exception)
        self.assertIn("CB-R1", message)  # 只暴露幂等标识
        for sensitive in ("伪造的账号名", "DY-FORGED", "改名后的账号名",
                          "https://video.example/comment/55"):
            self.assertNotIn(sensitive, message)  # 不泄露任何回调正文
        # 冲突内容未生效，首次结果仍可被相同重传取回
        self.assertEqual(len(self.callback_records()), 1)
        digest = self.app.incident_digest(self.incident_id)
        self.assertEqual(len(digest["证据依据"]["platform_receipts"]), 1)
        self.assertEqual(digest["证据依据"]["linked_accounts"][0]["display_name"], "改名后的账号名")
        again = self.app.platform_callback(removal_callback(self.incident_id))
        self.assertTrue(again["duplicate"])


class CallbackFaultInjectionTest(unittest.TestCase):
    """故障注入：进程在任一写入点中断后都能从追加式账本干净恢复。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "events.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def open_app(self):
        return SafeguardingApp(store_path=self.path)

    def test_crash_before_commit_leaves_no_trace_and_retry_succeeds(self):
        app = self.open_app()
        incident_id = app.submit_report(abuse_report(), AGENT)["incident_id"]
        # 故障注入：在回调提交账本记录的写入点进程崩溃
        def boom(*_args, **_kwargs):
            raise RuntimeError("模拟进程在写入点退出")
        app.store.append = boom
        with self.assertRaises(RuntimeError):
            app.platform_callback(removal_callback(incident_id))

        # 重启重放：没有任何回调痕迹，重传按首次处理干净生效
        recovered = self.open_app()
        self.assertEqual(recovered.callbacks, {})
        result = recovered.platform_callback(removal_callback(incident_id))
        self.assertFalse(result["duplicate"])
        digest = recovered.incident_digest(incident_id)
        self.assertEqual(len(digest["证据依据"]["platform_receipts"]), 1)
        self.assertEqual(recovered.list_notifications(), [])
        self.assertEqual(len(recovered.list_incidents()), 1)

    def test_crash_after_commit_recovers_idempotency_from_ledger(self):
        app = self.open_app()
        incident_id = app.submit_report(abuse_report(), AGENT)["incident_id"]
        first = app.platform_callback(removal_callback(incident_id))
        # 模拟进程在响应发出前退出：账本已提交、内存结果丢失 → 直接重启
        recovered = self.open_app()
        again = recovered.platform_callback(removal_callback(incident_id))
        self.assertTrue(again["duplicate"])
        self.assertEqual(without_duplicate_flag(again), without_duplicate_flag(first))
        # 不重复挂接、不重复通知、不产生第二案件
        digest = recovered.incident_digest(incident_id)
        self.assertEqual(len(digest["证据依据"]["platform_receipts"]), 1)
        history = digest["证据依据"]["linked_accounts"][0]["name_history"]
        self.assertEqual([h["name"] for h in history], ["辱骂账号", "改名后的账号名"])
        self.assertEqual(recovered.list_notifications(), [])
        self.assertEqual(len(recovered.list_incidents()), 1)
        # 重启后同标识异内容仍是冲突
        hostile = removal_callback(incident_id)
        hostile["account"]["display_name"] = "伪造的账号名"
        with self.assertRaises(AppError) as ctx:
            recovered.platform_callback(hostile)
        self.assertEqual(ctx.exception.status, 409)

    def test_legacy_partial_effects_converge_on_redelivery(self):
        """复现昨夜事故：旧实现已落回执与改名、已处理标记未落账时进程退出。"""
        app = self.open_app()
        incident_id = app.submit_report(abuse_report(), AGENT)["incident_id"]
        at = "2026-09-18T21:03:00+08:00"
        evidence_id = app.incidents[incident_id]["evidence"][0]["evidence_id"]
        # 旧实现崩溃前留下的半截效果（账本里没有 callback_processed 标记）
        app.store.append("receipt_recorded", {
            "incident_id": incident_id, "receipt_id": "DY-8840217", "platform": "douyin",
            "status": "removed", "reported_at": at, "via": "callback", "at": at})
        app.store.append("content_state_changed", {
            "incident_id": incident_id, "evidence_id": evidence_id,
            "old_state": "online", "new_state": "deleted",
            "source": "platform_callback", "at": at})
        app.store.append("account_renamed", {
            "incident_id": incident_id, "platform": "douyin", "account_key": "dy_hater_9",
            "old_name": "辱骂账号", "new_name": "改名后的账号名", "at": at})

        recovered = self.open_app()
        self.assertEqual(recovered.callbacks, {})  # 幂等索引确实未落账
        result = recovered.platform_callback(removal_callback(incident_id))
        self.assertFalse(result["duplicate"])  # 重传按首次处理……
        # ……但效果收敛：不重复挂回执、不重复改名、不重复通知、不产生第二案件
        digest = recovered.incident_digest(incident_id)
        self.assertEqual(len(digest["证据依据"]["platform_receipts"]), 1)
        history = digest["证据依据"]["linked_accounts"][0]["name_history"]
        self.assertEqual([h["name"] for h in history], ["辱骂账号", "改名后的账号名"])
        self.assertEqual(digest["证据依据"]["evidence"][0]["state"], "deleted")
        self.assertEqual(recovered.list_notifications(), [])
        self.assertEqual(len(recovered.list_incidents()), 1)
        # 此后相同重传返回已落账的首次结果
        again = recovered.platform_callback(removal_callback(incident_id))
        self.assertTrue(again["duplicate"])

    def test_torn_tail_line_is_ignored_on_recovery(self):
        app = self.open_app()
        incident_id = app.submit_report(abuse_report(), AGENT)["incident_id"]
        app.platform_callback(removal_callback(incident_id))
        # 模拟写入途中断电：账本末尾留下半行残缺记录
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write('{"event_id": "evt_torn", "type": "callback_pro')
        recovered = self.open_app()
        again = recovered.platform_callback(removal_callback(incident_id))
        self.assertTrue(again["duplicate"])
        digest = recovered.incident_digest(incident_id)
        self.assertEqual(len(digest["证据依据"]["platform_receipts"]), 1)
        self.assertEqual(len(recovered.list_incidents()), 1)


class CallbackConcurrencyTest(unittest.TestCase):
    """并发：同一 callback_id 并发到达时只有一个胜者（真实 HTTP 服务）。"""

    THREADS = 8

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.app = SafeguardingApp(store_path=os.path.join(cls.tmp.name, "events.jsonl"))
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

    def _post_callback(self, payload):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = Request(f"{self.base_url}/callbacks/platform", data=data, method="POST",
                          headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)

    def _race(self, payloads):
        barrier = threading.Barrier(len(payloads))
        results = [None] * len(payloads)

        def worker(index):
            barrier.wait(timeout=5)
            results[index] = self._post_callback(payloads[index])

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(len(payloads))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        self.assertTrue(all(r is not None for r in results))
        return results

    def callback_records(self, callback_id):
        return [e for e in self.app.store.replay()
                if e["type"] == "callback_processed"
                and e["payload"]["callback_id"] == callback_id]

    def test_concurrent_identical_callbacks_have_single_winner(self):
        url = "https://video.example/comment/race-same"
        incident_id = self.app.submit_report(abuse_report(
            victim_code="ATH-RACE-1", content_url=url), AGENT)["incident_id"]
        incident_count = len(self.app.list_incidents())
        payloads = [removal_callback(incident_id, "CB-RACE-SAME", content_url=url)
                    for _ in range(self.THREADS)]
        results = self._race(payloads)

        winners = [b for s, b in results if s == 200 and not b["duplicate"]]
        duplicates = [b for s, b in results if s == 200 and b["duplicate"]]
        self.assertEqual(len(winners), 1)  # 只有一个胜者
        self.assertEqual(len(duplicates), self.THREADS - 1)
        for body in duplicates:  # 其余全部拿到与首次一致的结果
            self.assertEqual(without_duplicate_flag(body), without_duplicate_flag(winners[0]))
        self.assertEqual(len(self.callback_records("CB-RACE-SAME")), 1)
        digest = self.app.incident_digest(incident_id)
        self.assertEqual(len(digest["证据依据"]["platform_receipts"]), 1)
        history = digest["证据依据"]["linked_accounts"][0]["name_history"]
        self.assertEqual([h["name"] for h in history], ["辱骂账号", "改名后的账号名"])
        self.assertEqual(self.app.list_notifications(incident_id), [])
        self.assertEqual(len(self.app.list_incidents()), incident_count)  # 没有第二案件

    def test_concurrent_conflicting_callbacks_have_single_winner(self):
        url = "https://video.example/comment/race-conflict"
        incident_id = self.app.submit_report(abuse_report(
            victim_code="ATH-RACE-2", content_url=url), AGENT)["incident_id"]
        incident_count = len(self.app.list_incidents())
        names = [f"并发名字-{i}" for i in range(self.THREADS)]
        payloads = [removal_callback(incident_id, "CB-RACE-CONFLICT", name=name,
                                     content_url=url)
                    for name in names]
        results = self._race(payloads)

        ok = [b for s, b in results if s == 200]
        conflicts = [b for s, b in results if s == 409]
        self.assertEqual(len(ok), 1)  # 只有一个胜者生效
        self.assertEqual(len(conflicts), self.THREADS - 1)
        self.assertFalse(ok[0]["duplicate"])
        # 冲突响应对外不泄露任何回调正文
        for body in conflicts:
            blob = json.dumps(body, ensure_ascii=False)
            for name in names:
                self.assertNotIn(name, blob)
            self.assertNotIn("DY-8840217", blob)
            self.assertNotIn(url, blob)
        # 账本只有胜者的一条记录，投影与胜者内容一致
        records = self.callback_records("CB-RACE-CONFLICT")
        self.assertEqual(len(records), 1)
        winner_name = records[0]["payload"]["effects"][-1][1]["new_name"]
        self.assertIn(winner_name, names)
        digest = self.app.incident_digest(incident_id)
        self.assertEqual(digest["证据依据"]["linked_accounts"][0]["display_name"], winner_name)
        self.assertEqual(len(digest["证据依据"]["platform_receipts"]), 1)
        self.assertEqual(self.app.list_notifications(incident_id), [])
        self.assertEqual(len(self.app.list_incidents()), incident_count)


class LateCallbackRoutingTest(unittest.TestCase):
    """迟到回调：归到正确的责任链，不把已合并/已关闭的旧事件重新打开。"""

    def setUp(self):
        self.app = SafeguardingApp()

    def test_late_callback_to_merged_incident_joins_survivor_chain(self):
        first_id = self.app.submit_report(threat_report(), AGENT)["incident_id"]
        self.app.acknowledge_escalation(first_id, DUTY)
        mirror_url = "https://weibo.example/comment/90210?mirror=1"
        second_id = self.app.submit_report(threat_report(
            content_url=mirror_url,
            receipts=[{"receipt_id": "WB-2026-09-18-7781", "platform": "weibo",
                       "status": "accepted"}]), AGENT)["incident_id"]
        self.app.acknowledge_escalation(second_id, DUTY)
        sugg_id = self.app.list_suggestions()[0]["suggestion_id"]
        self.app.resolve_suggestion(sugg_id, "accept", OFFICER, target_incident=first_id)
        notifications_before = len(self.app.list_notifications())

        late = {
            "callback_id": "CB-LATE-MERGE",
            "incident_id": second_id,  # 上游仍引用被合并的旧事件
            "receipt": {"receipt_id": "WB-LATE-9", "platform": "weibo",
                        "status": "removed", "content_url": mirror_url},
            "account": {"platform": "weibo", "account_key": "u_threat_77",
                        "display_name": "威胁者改名"},
        }
        result = self.app.platform_callback(late)
        self.assertFalse(result["duplicate"])
        self.assertEqual(result["incident_id"], first_id)  # 归到主事件责任链

        survivor = self.app.incident_digest(first_id)
        receipt_ids = [r["receipt_id"] for r in survivor["证据依据"]["platform_receipts"]]
        self.assertIn("WB-LATE-9", receipt_ids)
        chain_types = [c["type"] for c in survivor["责任链"]]
        for expected in ("callback_processed", "receipt_recorded",
                         "content_state_changed", "account_renamed"):
            self.assertIn(expected, chain_types)
        # 证据留在被合并事件上，其内容状态同样被正确更新
        absorbed_evidence = self.app.incidents[second_id]["evidence"][0]
        self.assertEqual(absorbed_evidence["state"], "deleted")
        # 旧事件没有被重新打开，也没有产生第二案件或新通知
        self.assertEqual(self.app.incidents[second_id]["merged_into"], first_id)
        self.assertEqual(self.app.incident_digest(second_id)["status"], "已关闭")
        self.assertEqual(len(self.app.list_incidents()), 2)
        self.assertEqual(len(self.app.list_notifications()), notifications_before)
        # 相同重传仍幂等，且仍归到主事件
        again = self.app.platform_callback(late)
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["incident_id"], first_id)

    def test_late_callback_to_closed_incident_attaches_without_reopening(self):
        incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]
        self.app.close_incident(incident_id, "保护动作完成", OFFICER)
        closed_at = self.app.incidents[incident_id]["closed_at"]

        result = self.app.platform_callback(removal_callback(incident_id, "CB-LATE-CLOSED"))
        self.assertFalse(result["duplicate"])
        digest = self.app.incident_digest(incident_id)
        self.assertEqual(digest["status"], "已关闭")  # 没有重新打开
        self.assertEqual(digest["closed_at"], closed_at)
        self.assertEqual(len(digest["证据依据"]["platform_receipts"]), 1)
        self.assertEqual(digest["证据依据"]["evidence"][0]["state"], "deleted")
        self.assertIn("callback_processed", [c["type"] for c in digest["责任链"]])
        self.assertEqual(len(self.app.list_incidents()), 1)
        self.assertEqual(self.app.list_notifications(), [])


class LedgerApiConsistencyTest(unittest.TestCase):
    """重启重放后，最终账本、投影与接口响应三者一致。"""

    def test_reloaded_ledger_matches_live_state_and_http_responses(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.jsonl")
            app = SafeguardingApp(store_path=path)
            incident_id = app.submit_report(abuse_report(
                receipts=[{"receipt_id": "DY-FIRST", "platform": "douyin",
                           "status": "accepted"}]), AGENT)["incident_id"]
            first = app.platform_callback(removal_callback(incident_id, "CB-C-1"))
            app.platform_callback(removal_callback(incident_id, "CB-C-1"))  # 相同重传
            with self.assertRaises(AppError):  # 同标识异内容 → 冲突
                app.platform_callback(removal_callback(incident_id, "CB-C-1", name="冲突名"))
            app.platform_callback(removal_callback(incident_id, "CB-C-2", name="再次改名"))
            app.close_incident(incident_id, "保护动作完成", OFFICER)
            app.platform_callback(removal_callback(incident_id, "CB-C-3", name="迟到改名"))

            live_digest = app.incident_digest(incident_id)
            live_reports = app.list_reports()
            live_callbacks = app.callbacks

            # 重启：仅从追加式账本重放
            reloaded = SafeguardingApp(store_path=path)
            self.assertEqual(
                json.dumps(reloaded.incident_digest(incident_id), ensure_ascii=False, sort_keys=True),
                json.dumps(live_digest, ensure_ascii=False, sort_keys=True))
            self.assertEqual(
                json.dumps(reloaded.list_reports(), ensure_ascii=False, sort_keys=True),
                json.dumps(live_reports, ensure_ascii=False, sort_keys=True))
            self.assertEqual(reloaded.callbacks, live_callbacks)
            self.assertEqual(reloaded.list_notifications(), [])

            # 接口响应与账本一致：相同重传返回首次结果，异内容仍是 409
            server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(reloaded))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                status, body = self._post(base, "/callbacks/platform",
                                          removal_callback(incident_id, "CB-C-1"))
                self.assertEqual(status, 200)
                self.assertTrue(body["duplicate"])
                self.assertEqual(without_duplicate_flag(body), without_duplicate_flag(first))

                status, body = self._post(base, "/callbacks/platform",
                                          removal_callback(incident_id, "CB-C-1", name="又一个伪造名"))
                self.assertEqual(status, 409)
                self.assertNotIn("又一个伪造名", json.dumps(body, ensure_ascii=False))

                with urlopen(f"{base}/incidents/{incident_id}/digest", timeout=3) as response:
                    digest = json.load(response)
                self.assertEqual(digest["status"], "已关闭")
                self.assertEqual(digest["证据依据"]["linked_accounts"][0]["display_name"],
                                 "迟到改名")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    @staticmethod
    def _post(base, path, payload):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = Request(f"{base}{path}", data=data, method="POST",
                          headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)


if __name__ == "__main__":
    unittest.main()
