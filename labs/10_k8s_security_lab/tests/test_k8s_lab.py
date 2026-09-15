#!/usr/bin/env python3
"""Unit test suite for Lab 10: Kubernetes & Container Security Lab.

Tests core terminal simulation, RBAC query logic, virtual file system,
pipeline execution, and security guards.
"""

import os
import sys
import unittest

# Ensure app directory is importable
APP_DIR = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, APP_DIR)

# Provide lightweight mock for fastapi/pydantic if running in environments without them
try:
    import fastapi
except ImportError:
    class MockFastAPI:
        def __init__(self, *args, **kwargs): pass
        def mount(self, *args, **kwargs): pass
        def get(self, *args, **kwargs): return lambda f: f
        def post(self, *args, **kwargs): return lambda f: f
    class MockStaticFiles:
        def __init__(self, *args, **kwargs): pass

    sys.modules["fastapi"] = type("fastapi_mod", (), {
        "FastAPI": MockFastAPI,
        "Request": object,
        "Header": lambda *a, **kw: None,
        "HTTPException": Exception,
    })
    sys.modules["fastapi.responses"] = type("resp_mod", (), {
        "HTMLResponse": str,
        "JSONResponse": dict,
    })
    sys.modules["fastapi.staticfiles"] = type("static_mod", (), {
        "StaticFiles": MockStaticFiles,
    })

try:
    import pydantic
except ImportError:
    class MockBaseModel:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    sys.modules["pydantic"] = type("pydantic_mod", (), {"BaseModel": MockBaseModel})

import main


class TestK8sLabSimulation(unittest.TestCase):
    def setUp(self):
        main.cluster.reset()

    def test_virtual_fs_sa_token_access(self):
        """Test reading the serviceaccount token from virtual filesystem."""
        res = main.execute_single_cmd("cat /var/run/secrets/kubernetes.io/serviceaccount/token")
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("eyJhbGci", res["output"])
        self.assertTrue(main.cluster.solved["ch1"])

    def test_directory_navigation_cd(self):
        """Test cd command and relative path tracking."""
        res = main.execute_single_cmd("cd /var/run/secrets")
        self.assertEqual(res["exit_code"], 0)
        self.assertEqual(main.cluster.term_cwd, "/var/run/secrets")

        res_pwd = main.execute_single_cmd("pwd")
        self.assertEqual(res_pwd["output"], "/var/run/secrets")

        res_cd_root = main.execute_single_cmd("cd ~")
        self.assertEqual(res_cd_root["exit_code"], 0)
        self.assertEqual(main.cluster.term_cwd, "/root")

    def test_kubectl_auth_can_i(self):
        """Test kubectl auth can-i command simulation."""
        res_sec = main.execute_single_cmd("kubectl auth can-i list secrets")
        self.assertEqual(res_sec["exit_code"], 0)
        self.assertEqual(res_sec["output"], "yes")

        res_del = main.execute_single_cmd("kubectl auth can-i delete nodes")
        self.assertEqual(res_del["exit_code"], 0)
        self.assertEqual(res_del["output"], "no")

    def test_pipeline_execution(self):
        """Test pipeline execution: echo <b64> | base64 -d."""
        req = main.ExecRequest(command="echo 'RkxBR3tURVNUX0ZMQUd9' | base64 -d")
        res = main.terminal_exec(req)
        self.assertEqual(res["exit_code"], 0)
        self.assertEqual(res["output"], "FLAG{TEST_FLAG}")

    def test_kubectl_get_secrets_dumps_ch2(self):
        """Test kubectl get secrets lists secrets and triggers ch2 solve."""
        res = main.execute_single_cmd("kubectl get secrets -n production")
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("db-root-credentials", res["output"])
        self.assertTrue(main.cluster.solved["ch2"])

    def test_hostpath_creation_and_escape(self):
        """Test evil pod creation and host flag exfiltration."""
        self.assertFalse(main.cluster.hostpath_pod_created)
        apply_res = main.execute_single_cmd("kubectl apply -f evil-pod.yaml")
        self.assertEqual(apply_res["exit_code"], 0)
        self.assertTrue(main.cluster.hostpath_pod_created)

        # Read host flag
        cat_res = main.execute_single_cmd("cat /host/root/host_flag.txt")
        self.assertEqual(cat_res["exit_code"], 0)
        self.assertIn("FLAG{K8S_HOSTPATH_ESCAPE_NODE_ROOT_ACCESS}", cat_res["output"])
        self.assertTrue(main.cluster.solved["ch3"])

    def test_nsenter_breakout_ch4(self):
        """Test nsenter container escape triggering ch4 solve."""
        res = main.execute_single_cmd("nsenter --target 1 --mount --uts --ipc --net --pid /bin/bash")
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("FLAG{K8S_PRIVILEGED_POD_ESCAPE_CLUSTER_TAKEOVER}", res["output"])
        self.assertTrue(main.cluster.solved["ch4"])
        self.assertTrue(main.cluster.cluster_takeover_achieved)

    def test_security_dos_command_length(self):
        """Test command length limit protection (DoS defense)."""
        huge_cmd = "a" * 5000
        req = main.ExecRequest(command=huge_cmd)
        res = main.terminal_exec(req)
        self.assertEqual(res["exit_code"], 1)
        self.assertIn("exceeds maximum allowed limit", res["output"])

    def test_syntax_error_graceful_handling(self):
        """Test unclosed quotes error handling."""
        res = main.execute_single_cmd("echo 'unclosed quote")
        self.assertEqual(res["exit_code"], 2)
        self.assertIn("syntax error", res["output"])

    def test_flag_verification_valid(self):
        """Test valid flag verification."""
        req = main.FlagVerifyRequest(flag="FLAG{K8S_SA_TOKEN_LEAKED_SECRET_RECON}")
        res = main.verify_flag(req)
        self.assertTrue(res["success"])
        self.assertEqual(res["challenge"], "ch1")
        self.assertTrue(main.cluster.solved["ch1"])

    def test_flag_verification_invalid_format(self):
        """Test flag format rejection."""
        req = main.FlagVerifyRequest(flag="INVALID_NO_WRAPPER")
        res = main.verify_flag(req)
        self.assertFalse(res["success"])
        self.assertIn("Invalid flag format", res["message"])

    def test_flag_verification_length_limit(self):
        """Test flag length limit rejection."""
        req = main.FlagVerifyRequest(flag="FLAG{" + "A" * 150 + "}")
        res = main.verify_flag(req)
        self.assertFalse(res["success"])
        self.assertIn("length out of bounds", res["message"])


if __name__ == "__main__":
    unittest.main()
