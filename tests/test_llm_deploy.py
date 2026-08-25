import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class LLMDeploymentTest(unittest.TestCase):
    def test_systemd_unit_has_required_isolation(self):
        unit = (ROOT / "deploy" / "systemd" / "kdiag-llm.service").read_text(encoding="utf-8")
        for required in (
            "User=kdiag-llm",
            "NoNewPrivileges=true",
            "CapabilityBoundingSet=\n",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "IPAddressDeny=any",
            "IPAddressAllow=127.0.0.0/8",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "--offline",
            "--log-disable",
            "--no-webui",
            "--no-agent",
        ):
            self.assertIn(required, unit)
        self.assertNotIn("User=root", unit)

    def test_environment_is_loopback_offline_and_has_no_remote_model_source(self):
        environment = (ROOT / "deploy" / "systemd" / "llama-server.env.example").read_text(encoding="utf-8")
        self.assertIn("LLAMA_ARG_HOST=127.0.0.1", environment)
        self.assertIn("LLAMA_ARG_OFFLINE=true", environment)
        self.assertIn("LLAMA_ARG_UI=false", environment)
        self.assertIn("LLAMA_ARG_AGENT=false", environment)
        self.assertIn("LLAMA_ARG_MODEL=/opt/kdiag-llm/models/model.gguf", environment)
        for forbidden in ("MODEL_URL", "HF_REPO", "HF_TOKEN", "MCP_SERVERS", "ARG_TOOLS"):
            self.assertNotIn(forbidden, environment)


if __name__ == "__main__":
    unittest.main()
