"""Vouch control plane (:9002) — tenant provisioning, key authority,
policy store, deployments, service tokens (Phase 2, §4.4/§4.5).

Tenant endpoints (/v1/*) take `vouch_sk_*` API keys. Internal endpoints
(/internal/*) take service-token bearers minted by
`python3 -m services.controlplane.seed_tokens`. Key material (HMAC keys,
key plaintext) never appears in a response except at creation time
(shown once).

Endpoints:
    POST /v1/tenants                      open (provisioning)
    GET  /v1/tenants/me                   tenant key
    POST /v1/tenants/me/rotate-keys      tenant key
    POST /v1/api-keys                    tenant key
    GET  /v1/api-keys                    tenant key
    DELETE /v1/api-keys/{id}             tenant key
    GET  /v1/policies                    tenant key
    PUT  /v1/policies/{task_id}          tenant key  (422 on invalid rules)
    DELETE /v1/policies/{task_id}        tenant key
    POST /v1/deployments                  tenant key
    GET  /v1/deployments                  tenant key
    GET  /v1/deployments/{id}            tenant key
    DELETE /v1/deployments/{id}          tenant key  (-> stopped)
    GET  /internal/tenants/{id}/key-bundle  service token  (§4.3)
    GET  /internal/tenants/{id}/keys        service token  (§4.7)
    GET  /internal/policies/bundle?tenant_id=&since_version=  service token (§4.4)
    POST /internal/cache/invalidate      service token  (§4.3, best-effort push)
    GET  /internal/desired-state         service token  (§4.5)
    POST /internal/deployments/{id}/status  service token (§4.5)
    POST /internal/tenants/{id}/plan     service token  (§4.8 billing hook)
    POST /internal/tenants/{id}/status   service token  (suspension wiring)

Errors: {"error": "<code>", "message": "<human>"} with HTTP status (§4).

Run:  python3 -m services.controlplane.app
Env:  CONTROLPLANE_PORT    (default 9002)
      CONTROLPLANE_DB      (default <repo>/data/controlplane.db)
      GATEKEEPER_URL       gatekeeper base for push-invalidate (default "";
                           empty disables the push — the 60s TTL is the backstop)
      CONTROLPLANE_INVALIDATE_TOKEN  bearer the gatekeeper accepts on
                           /internal/cache/invalidate (default "")
      RECEIPT_SVC_URL      receipt service base for usage fan-in
                           (default http://127.0.0.1:9001)
      RECEIPT_FANIN_TOKEN  bearer for receipt-service /internal/usage (default "")
"""
import json
import os
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .models import ControlPlaneDB, PLANS, STATUSES

HERE = os.path.dirname(__file__)
PORT = int(os.environ.get("CONTROLPLANE_PORT", "9002"))
DB_PATH = os.environ.get(
    "CONTROLPLANE_DB", os.path.join(HERE, "..", "..", "data", "controlplane.db"))
GATEKEEPER_URL = os.environ.get("GATEKEEPER_URL", "").rstrip("/")
INVALIDATE_TOKEN = os.environ.get("CONTROLPLANE_INVALIDATE_TOKEN", "")
RECEIPT_SVC_URL = os.environ.get(
    "RECEIPT_SVC_URL", "http://127.0.0.1:9001").rstrip("/")
RECEIPT_FANIN_TOKEN = os.environ.get("RECEIPT_FANIN_TOKEN", "")


class Handler(BaseHTTPRequestHandler):
    db = None  # ControlPlaneDB, set in main()

    server_version = "VouchControlPlane/1.0"

    # ------------------------------------------------------------ helpers
    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _err(self, code, error, message=""):
        self._send(code, {"error": error, "message": message or error})

    def _send_empty(self, code):
        """Status with no body (204 must not carry one)."""
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _path(self):
        u = urlparse(self.path)
        return u.path, {k: v[0] for k, v in parse_qs(u.query).items()}

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        try:
            body = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            return "INVALID"
        return body if isinstance(body, dict) else "INVALID"

    def _bearer(self):
        auth = self.headers.get("Authorization", "")
        return auth[7:] if auth.startswith("Bearer ") else ""

    def _tenant(self):
        """Tenant row for a vouch_sk_* bearer, or None."""
        return self.db.get_tenant_by_api_key(self._bearer())

    def _service(self):
        """Service-token name for a service bearer, or None."""
        return self.db.validate_service_token(self._bearer())

    def _require_tenant(self):
        t = self._tenant()
        if t is None:
            self._err(401, "unauthorized", "valid vouch_sk_* API key required")
            return None
        return t

    def _require_service(self):
        name = self._service()
        if name is None:
            self._err(401, "unauthorized", "valid service token required")
            return None
        return name

    @classmethod
    def _push_invalidate(cls, tenant_id):
        """Best-effort: tell the gatekeeper to drop a cached key bundle.

        Never raises; the gatekeeper's 60s TTL is the backstop. Wire it by
        setting GATEKEEPER_URL and CONTROLPLANE_INVALIDATE_TOKEN (to the
        same value as the gatekeeper's GATEKEEPER_SVC_TOKEN).
        """
        if not GATEKEEPER_URL or not INVALIDATE_TOKEN:
            return
        try:
            req = urllib.request.Request(
                GATEKEEPER_URL + "/internal/cache/invalidate",
                data=json.dumps({"tenant_id": tenant_id}).encode("utf-8"),
                headers={"Content-Type": "application/json",
                         "Authorization": f"Bearer {INVALIDATE_TOKEN}"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=3).read()
        except Exception:  # noqa: BLE001 - best-effort by design
            pass

    def _usage_for(self, tenant_id):
        """Usage block for GET /v1/tenants/me — fans in to the receipt service.

        Best-effort: without RECEIPT_FANIN_TOKEN configured this reports
        zeros rather than failing the tenant call.
        """
        month = time.strftime("%Y-%m", time.gmtime())
        usage = {"month": month, "actions_allowed": 0, "actions_denied": 0}
        if RECEIPT_SVC_URL and RECEIPT_FANIN_TOKEN:
            try:
                req = urllib.request.Request(
                    f"{RECEIPT_SVC_URL}/internal/usage/{tenant_id}?month={month}",
                    headers={"Authorization": f"Bearer {RECEIPT_FANIN_TOKEN}"},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                usage["actions_allowed"] = int(data.get("actions_allowed", 0))
                usage["actions_denied"] = int(data.get("actions_denied", 0))
            except Exception:  # noqa: BLE001 - fan-in is best-effort
                pass
        return usage

    def log_message(self, *a):  # quieter logs
        pass

    # ---------------------------------------------------------------- GET
    def do_GET(self):
        path, q = self._path()
        if path == "/v1/tenants/me":
            return self._get_me()
        if path == "/v1/api-keys":
            return self._list_api_keys()
        if path == "/v1/policies":
            return self._get_policies()
        if path == "/v1/deployments":
            return self._list_deployments()
        if path.startswith("/v1/deployments/"):
            return self._get_deployment(path)
        if path.startswith("/internal/tenants/"):
            return self._internal_tenant_get(path)
        if path == "/internal/policies/bundle":
            return self._internal_bundle(q)
        if path == "/internal/desired-state":
            return self._internal_desired_state()
        return self._err(404, "not_found")

    def _get_me(self):
        t = self._require_tenant()
        if t is None:
            return
        self._send(200, {
            "tenant_id": t["id"],
            "name": t["name"],
            "plan": t["plan"],
            "status": t["status"],
            "usage": self._usage_for(t["id"]),
        })

    def _list_api_keys(self):
        t = self._require_tenant()
        if t is None:
            return
        self._send(200, {"keys": self.db.list_api_keys(t["id"])})

    def _get_policies(self):
        t = self._require_tenant()
        if t is None:
            return
        self._send(200, {"tasks": self.db.get_policies(t["id"])})

    def _list_deployments(self):
        t = self._require_tenant()
        if t is None:
            return
        self._send(200, {"deployments": self.db.list_deployments(t["id"])})

    def _get_deployment(self, path):
        t = self._require_tenant()
        if t is None:
            return
        dep = self.db.get_deployment(t["id"], path[len("/v1/deployments/"):])
        if dep is None:
            return self._err(404, "not_found", "deployment not found")
        self._send(200, dep)

    def _internal_tenant_get(self, path):
        if self._require_service() is None:
            return
        rest = path[len("/internal/tenants/"):]  # {id}/key-bundle | {id}/keys
        tenant_id, _, tail = rest.partition("/")
        if tail == "key-bundle":
            bundle = self.db.key_bundle(tenant_id)
            if bundle is None:
                return self._err(404, "unknown_tenant")
            return self._send(200, bundle)
        if tail == "keys":
            keys = self.db.get_keys(tenant_id)
            if keys is None:
                return self._err(404, "unknown_tenant")
            return self._send(200, keys)
        return self._err(404, "not_found")

    def _internal_bundle(self, q):
        if self._require_service() is None:
            return
        tenant_id = q.get("tenant_id", "")
        if not tenant_id:
            return self._err(400, "bad_request", "tenant_id query param required")
        try:
            since = int(q.get("since_version", 0) or 0)
        except (TypeError, ValueError):
            return self._err(400, "bad_request", "since_version must be an integer")
        result = self.db.policy_bundle(tenant_id, since)
        if result is None:
            return self._err(404, "unknown_tenant")
        version, policies = result
        self._send(200, {"version": version, "policies": policies})

    def _internal_desired_state(self):
        if self._require_service() is None:
            return
        self._send(200, {"deployments": self.db.desired_state()})

    # ---------------------------------------------------------------- POST
    def do_POST(self):
        path, _ = self._path()
        if path == "/v1/tenants":
            return self._create_tenant()
        if path == "/v1/tenants/me/rotate-keys":
            return self._rotate_keys()
        if path == "/v1/api-keys":
            return self._create_api_key()
        if path == "/v1/deployments":
            return self._create_deployment()
        if path == "/internal/cache/invalidate":
            return self._internal_invalidate()
        if path.startswith("/internal/deployments/"):
            return self._internal_deployment_status(path)
        if path.startswith("/internal/tenants/"):
            return self._internal_tenant_post(path)
        return self._err(404, "not_found")

    def _create_tenant(self):
        body = self._read_json()
        if body == "INVALID":
            return self._err(400, "bad_request", "body must be a JSON object")
        try:
            result = self.db.create_tenant(body.get("name", ""))
        except ValueError as e:
            return self._err(400, "bad_request", str(e))
        # api_key plaintext is shown exactly once, here.
        self._send(201, result)

    def _rotate_keys(self):
        t = self._require_tenant()
        if t is None:
            return
        new_kid = self.db.rotate_keys(t["id"])
        self._push_invalidate(t["id"])
        # only the new kid is returned — key material never leaves otherwise
        self._send(200, {"new_kid": new_kid})

    def _create_api_key(self):
        t = self._require_tenant()
        if t is None:
            return
        body = self._read_json()
        if body == "INVALID":
            return self._err(400, "bad_request", "body must be a JSON object")
        try:
            result = self.db.create_api_key(t["id"], body.get("name", ""))
        except (ValueError, KeyError) as e:
            return self._err(400, "bad_request", str(e))
        self._send(201, result)

    def _create_deployment(self):
        t = self._require_tenant()
        if t is None:
            return
        body = self._read_json()
        if body == "INVALID":
            return self._err(400, "bad_request", "body must be a JSON object")
        try:
            result = self.db.create_deployment(
                t["id"], body.get("task_id", ""), body.get("agent_image", ""))
        except (ValueError, KeyError) as e:
            return self._err(400, "bad_request", str(e))
        self._send(201, result)

    def _internal_invalidate(self):
        if self._require_service() is None:
            return
        body = self._read_json()
        if body == "INVALID":
            return self._err(400, "bad_request", "body must be a JSON object")
        tenant_id = body.get("tenant_id", "")
        if not tenant_id:
            return self._err(400, "bad_request", "tenant_id required")
        self._push_invalidate(tenant_id)
        self._send(200, {"ok": True, "tenant_id": tenant_id})

    def _internal_deployment_status(self, path):
        if self._require_service() is None:
            return
        # /internal/deployments/{id}/status
        rest = path[len("/internal/deployments/"):]
        dep_id, _, tail = rest.partition("/")
        if tail != "status":
            return self._err(404, "not_found")
        body = self._read_json()
        if body == "INVALID":
            return self._err(400, "bad_request", "body must be a JSON object")
        try:
            ok = self.db.set_deployment_status(
                dep_id, body.get("status", ""),
                container_id=body.get("container_id"))
        except ValueError as e:
            return self._err(400, "bad_request", str(e))
        if not ok:
            return self._err(404, "not_found", "deployment not found")
        self._send(200, {"ok": True})

    def _internal_tenant_post(self, path):
        if self._require_service() is None:
            return
        # /internal/tenants/{id}/plan | /internal/tenants/{id}/status
        rest = path[len("/internal/tenants/"):]
        tenant_id, _, tail = rest.partition("/")
        body = self._read_json()
        if body == "INVALID":
            return self._err(400, "bad_request", "body must be a JSON object")
        if tail == "plan":
            try:
                ok = self.db.set_plan(tenant_id, body.get("plan", ""))
            except ValueError as e:
                return self._err(422, "invalid_plan", str(e))
            if not ok:
                return self._err(404, "unknown_tenant")
            self._push_invalidate(tenant_id)
            return self._send(200, {"ok": True, "plan": body["plan"]})
        if tail == "status":
            try:
                ok = self.db.set_status(tenant_id, body.get("status", ""))
            except ValueError as e:
                return self._err(422, "invalid_status", str(e))
            if not ok:
                return self._err(404, "unknown_tenant")
            self._push_invalidate(tenant_id)
            return self._send(200, {"ok": True, "status": body["status"]})
        return self._err(404, "not_found")

    # ---------------------------------------------------------------- PUT
    def do_PUT(self):
        path, _ = self._path()
        if path.startswith("/v1/policies/"):
            return self._put_policy(path[len("/v1/policies/"):])
        return self._err(404, "not_found")

    def _put_policy(self, task_id):
        t = self._require_tenant()
        if t is None:
            return
        body = self._read_json()
        if body == "INVALID":
            return self._err(400, "bad_request", "body must be a JSON object")
        try:
            version = self.db.put_policy(
                t["id"], task_id, body.get("rules"), updated_by=t["id"])
        except KeyError:
            return self._err(404, "unknown_tenant")
        except ValueError as e:
            # schema violations, unknown constraint ops -> 422 (§4.4)
            return self._err(422, "invalid_policy", str(e))
        self._send(200, {"task_id": task_id, "version": version})

    # -------------------------------------------------------------- DELETE
    def do_DELETE(self):
        path, _ = self._path()
        if path.startswith("/v1/api-keys/"):
            return self._delete_api_key(path[len("/v1/api-keys/"):])
        if path.startswith("/v1/policies/"):
            return self._delete_policy(path[len("/v1/policies/"):])
        if path.startswith("/v1/deployments/"):
            return self._delete_deployment(path[len("/v1/deployments/"):])
        return self._err(404, "not_found")

    def _delete_api_key(self, key_id):
        t = self._require_tenant()
        if t is None:
            return
        result = self.db.revoke_api_key(t["id"], key_id)
        if result is False:
            return self._err(404, "not_found", "api key not found")
        self._send_empty(204)

    def _delete_policy(self, task_id):
        t = self._require_tenant()
        if t is None:
            return
        if not self.db.delete_policy(t["id"], task_id):
            return self._err(404, "not_found", "no policy for task")
        self._send_empty(204)

    def _delete_deployment(self, dep_id):
        t = self._require_tenant()
        if t is None:
            return
        if not self.db.stop_deployment(t["id"], dep_id):
            return self._err(404, "not_found", "deployment not found")
        self._send(200, {"deployment_id": dep_id, "status": "stopped"})


def main():
    Handler.db = ControlPlaneDB(DB_PATH)
    print(f"vouch control plane listening on :{PORT}")
    print(f"db:      {DB_PATH}")
    if GATEKEEPER_URL:
        print(f"gatekeeper push-invalidate: {GATEKEEPER_URL}")
    else:
        print("gatekeeper push-invalidate: disabled (60s TTL is the backstop)")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
