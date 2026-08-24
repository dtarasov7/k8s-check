import unittest

from kdiag.inventory import parse_ansible_inventory


class InventoryTest(unittest.TestCase):
    def test_group_and_hostvars_are_normalized(self):
        document = {
            "_meta": {"hostvars": {"worker-1": {"ansible_host": "10.0.0.11", "ansible_user": "ops", "ansible_port": 2222}}},
            "workers": {"hosts": ["worker-1"], "children": []},
        }
        hosts = parse_ansible_inventory(document, group="workers")
        self.assertEqual(1, len(hosts))
        self.assertEqual("worker-1", hosts[0].name)
        self.assertEqual("10.0.0.11", hosts[0].target)
        self.assertEqual("ops@10.0.0.11", hosts[0].ssh_destination)
        self.assertEqual(2222, hosts[0].port)

    def test_shell_like_ssh_args_are_rejected(self):
        document = {
            "_meta": {"hostvars": {"worker-1": {"ansible_ssh_common_args": "-o ProxyCommand=bad"}}},
            "workers": {"hosts": ["worker-1"]},
        }
        with self.assertRaises(ValueError):
            parse_ansible_inventory(document, group="workers")


if __name__ == "__main__":
    unittest.main()
