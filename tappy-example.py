from tap.parser import Parser

output = """
TAP version 13
1..3
DsMakeSpn: HTTP/LAB1-W2K8R2-GW.lab1.awake.local
ok 1 - TestDsMakeSpn # 0.004000
ok 2 - TestDsCrackNames # 0.000000
ok 3 - TestDsCrackNames # SKIP
[100%] Built target kos-qemu-image-TestDsParse-sim
"""

lines = []
parser = Parser()
for line in parser.parse_text(output):
    if line.category == "test":
        d = line.directive
        print(line.ok, line.description, line.skip, d.text)
    if line.category == "plan":
        print(line.expected_tests)
