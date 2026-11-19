from pathlib import Path
import tempfile
import unittest

import codeflow


class CodeFlowTests(unittest.TestCase):
    def analyze(self, source: str):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lab.py"
            path.write_text(source, encoding="utf-8")
            tree, _ = codeflow.parse_file(path)
            return codeflow.TaintAnalyzer(tree, str(path)).analyze()

    def test_parse_and_print_function_names(self):
        tree = codeflow.ast.parse("def alpha():\n    pass\n\ndef beta():\n    pass\n")
        names = [
            node.name
            for node in codeflow.ast.walk(tree)
            if isinstance(node, codeflow.ast.FunctionDef)
        ]
        self.assertEqual(names, ["alpha", "beta"])

    def test_sources_only_selected_calls_are_tainted(self):
        flows = self.analyze(
            "a = input()\n"
            "b = str(a)\n"
            "eval(a)\n"
            "print(b)\n"
        )
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].source_line, 1)
        self.assertEqual(flows[0].sink_line, 3)

    def test_assignment_chain_is_tainted(self):
        flows = self.analyze("x = input()\ny = x\nexec(y)\n")
        self.assertEqual(len(flows), 1)
        self.assertIn("exec", flows[0].sink)

    def test_clean_sink_is_not_reported(self):
        flows = self.analyze("safe = 'hello'\nos.system('echo hello')\n")
        self.assertEqual(flows, [])

    def test_cross_function_argument_is_traced(self):
        flows = self.analyze(
            "def run(command):\n"
            "    os.system(command)\n"
            "\n"
            "data = input()\n"
            "run(data)\n"
        )
        sink_flows = [flow for flow in flows if flow.sink_kind == "command_execution"]
        self.assertEqual(len(sink_flows), 1)
        self.assertEqual(sink_flows[0].sink_line, 2)

    def test_database_sink_concatenated_query(self):
        flows = self.analyze(
            "name = input()\n"
            "cursor.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n"
        )
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].sink_kind, "sql_query")

    def test_parameterized_query_is_safe(self):
        flows = self.analyze(
            "name = input()\n"
            "cursor.execute('SELECT * FROM users WHERE name = ?', (name,))\n"
        )
        self.assertEqual(flows, [])

    def test_reassigned_clean_value_is_not_reported(self):
        flows = self.analyze("m = input()\nm = 'safe'\nos.system(m)\n")
        self.assertEqual(flows, [])

    def test_method_call_keeps_taint(self):
        flows = self.analyze("z = input()\nw = z.strip()\nos.system(w)\n")
        self.assertEqual(len(flows), 1)

    def test_for_loop_over_file_is_tainted(self):
        flows = self.analyze("for line in open('f.txt'):\n    eval(line)\n")
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].sink_line, 2)

    def test_with_open_is_tainted(self):
        flows = self.analyze(
            "with open('f.txt') as f:\n    data = f.read()\nos.system(data)\n"
        )
        self.assertEqual(len(flows), 1)

    def test_taint_inside_if_branch(self):
        flows = self.analyze(
            "if True:\n    x = input()\n    eval(x)\n"
        )
        self.assertEqual(len(flows), 1)

    def test_sanitizer_blocks_flow(self):
        flows = self.analyze(
            "import shlex\nx = input()\nos.system('echo ' + shlex.quote(x))\n"
        )
        self.assertEqual(flows, [])

    def test_class_method_is_traced(self):
        flows = self.analyze(
            "class A:\n"
            "    def go(self, c):\n"
            "        os.system(c)\n"
            "A().go(input())\n"
        )
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].sink_line, 3)

    def test_multiple_assignment_targets(self):
        flows = self.analyze("a = b = input()\neval(b)\n")
        self.assertEqual(len(flows), 1)

    def test_subprocess_list_without_shell_is_safe(self):
        flows = self.analyze("x = input()\nsubprocess.run(['echo', x])\n")
        self.assertEqual(flows, [])

    def test_subprocess_shell_true_is_reported(self):
        flows = self.analyze("x = input()\nsubprocess.run('echo ' + x, shell=True)\n")
        self.assertEqual(len(flows), 1)


if __name__ == "__main__":
    unittest.main()
