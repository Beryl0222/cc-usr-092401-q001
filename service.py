"""运动员网络权益保护的运行入口。

提供健康检查与事件处置的 HTTP 接口。业务规则见 app.py。
默认使用内存账本；传入 --data <path.jsonl> 可启用追加式持久化账本。
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from app import AppError, SafeguardingApp, suggest_severity

SERVICE_ID = "athlete-safeguarding"
SERVICE_NAME = "运动员网络权益保护"


def health_payload():
    """返回稳定的服务身份信息。"""
    return {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME}


def build_handler(app):
    """生成绑定到指定应用实例的 Handler（便于测试隔离与多账本部署）。"""

    class Handler(BaseHTTPRequestHandler):
        def _send_json(self, status, payload):
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self):
            length = int(self.headers.get("Content-Length") or 0)
            if not length:
                return {}
            try:
                return json.loads(self.rfile.read(length).decode("utf-8"))
            except json.JSONDecodeError:
                raise AppError("请求体不是合法 JSON")

        def _actor(self, body):
            actor = body.pop("actor", None) or {}
            if isinstance(actor, str):
                actor = {"name": actor}
            return actor

        def do_GET(self):
            parsed = urlparse(self.path)
            query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            try:
                if parsed.path == "/health":
                    self._send_json(200, health_payload())
                elif parsed.path == "/domain":
                    self._send_json(200, app.config.data)
                elif parsed.path == "/reports":
                    self._send_json(200, {"reports": app.list_reports()})
                elif parsed.path == "/incidents":
                    self._send_json(200, {"incidents": app.list_incidents(
                        status=query.get("status"), severity=query.get("severity"))})
                elif parsed.path.startswith("/incidents/") and parsed.path.endswith("/digest"):
                    incident_id = parsed.path.split("/")[2]
                    self._send_json(200, app.incident_digest(
                        incident_id, as_role=query.get("as_role")))
                elif parsed.path == "/suggestions":
                    self._send_json(200, {"suggestions": app.list_suggestions(
                        status=query.get("status", "open"))})
                elif parsed.path == "/notifications":
                    self._send_json(200, {"notifications": app.list_notifications(
                        incident_id=query.get("incident_id"))})
                else:
                    self._send_json(404, {"error": "路由不存在", "path": parsed.path})
            except AppError as error:
                self._send_json(error.status, {"error": str(error)})

        def do_POST(self):
            parsed = urlparse(self.path)
            path = parsed.path
            parts = [p for p in path.split("/") if p]
            try:
                body = self._read_body()

                if path == "/reports":
                    actor = self._actor(body)
                    result = app.submit_report(body, actor)
                    self._send_json(201 if result.get("incident_id") else 200, result)

                elif path == "/callbacks/platform":
                    # 平台回调：幂等键在体内，不带操作角色
                    self._send_json(200, app.platform_callback(body))

                elif path == "/severity/suggest":
                    # 联调辅助：仅给严重度建议，最终等级以人工填报为准
                    text = body.get("raw_excerpt", "")
                    self._send_json(200, {"text_excerpt": text[:40],
                                          "suggested_severity": suggest_severity(text)})

                elif len(parts) >= 3 and parts[0] == "incidents":
                    incident_id = parts[1]
                    actor = self._actor(body)
                    rest = parts[2:]
                    result = {"status": "ok"}
                    if rest == ["severity"]:
                        app.confirm_severity(incident_id, body.get("severity"), actor)
                        result = {"status": "已记录"}
                    elif rest == ["escalation", "ack"]:
                        app.acknowledge_escalation(incident_id, actor)
                        result = {"status": "升级已响应"}
                    elif rest == ["evidence"]:
                        result = app.add_evidence(incident_id, body, actor)
                        self._send_json(201, result)
                        return
                    elif rest == ["accounts"]:
                        result = app.link_account(incident_id, body, actor)
                        self._send_json(201, result)
                        return
                    elif rest == ["actions"]:
                        result = app.propose_action(
                            incident_id, body.get("action_type"), actor,
                            params=body.get("params"))
                        self._send_json(201, result)
                        return
                    elif rest == ["consent", "grant"]:
                        result = app.grant_consent(incident_id, body.get("scopes", []), actor)
                    elif rest == ["consent", "revoke"]:
                        result = app.revoke_consent(incident_id, body.get("scopes", []), actor)
                    elif rest == ["appeal"]:
                        app.open_appeal(incident_id, body.get("reason", ""), actor)
                        result = {"status": "申诉中"}
                    elif rest == ["appeal", "resolve"]:
                        app.resolve_appeal(incident_id, body.get("decision"), actor,
                                           note=body.get("note"))
                        result = {"status": "申诉已裁定", "decision": body.get("decision")}
                    elif rest == ["close"]:
                        app.close_incident(incident_id, body.get("reason"), actor)
                        result = {"status": "已关闭"}
                    else:
                        self._send_json(404, {"error": "事件子路由不存在", "path": path})
                        return
                    self._send_json(200, result)

                elif len(parts) == 3 and parts[0] == "actions":
                    action_id = parts[1]
                    actor = self._actor(body)
                    if parts[2] == "review":
                        result = app.review_action(action_id, body.get("decision"), actor,
                                                   reason=body.get("reason"))
                    elif parts[2] == "execute":
                        result = app.execute_action(action_id, actor)
                    else:
                        self._send_json(404, {"error": "动作子路由不存在", "path": path})
                        return
                    self._send_json(200, result)

                elif len(parts) == 3 and parts[0] == "suggestions":
                    actor = self._actor(body)
                    result = app.resolve_suggestion(
                        parts[1], body.get("decision"), actor,
                        target_incident=body.get("target_incident"))
                    self._send_json(200, result)

                else:
                    self._send_json(404, {"error": "路由不存在", "path": path})
            except AppError as error:
                self._send_json(error.status, {"error": str(error)})

        def log_message(self, *_args):
            return

    return Handler


# 默认内存应用；服务脚本通过 --data 替换为持久化账本
default_app = SafeguardingApp()
Handler = build_handler(default_app)


def create_server(port, app=None):
    handler = build_handler(app) if app else Handler
    return ThreadingHTTPServer(("0.0.0.0", port), handler)


def main():
    parser = argparse.ArgumentParser(description=SERVICE_NAME)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--data", help="追加式事件账本路径（.jsonl），缺省为内存账本")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        assert health_payload()["service"] == SERVICE_ID
        load_check = SafeguardingApp(store_path=args.data)
        assert load_check.config.severities["direct_threat"]["自动升级"] is True
        print(f"基础检查通过；严重度 {len(load_check.config.severities)} 项，"
              f"处置动作 {len(load_check.config.actions)} 类，事件 {len(load_check.incidents)} 件")
        return
    app = SafeguardingApp(store_path=args.data)
    create_server(args.port, app).serve_forever()


if __name__ == "__main__":
    main()
