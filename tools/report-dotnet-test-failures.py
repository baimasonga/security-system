"""Expose bounded synthetic CI test failures without requiring private log-storage access."""
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

namespace = {"t": "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"}
count = 0
for path in pathlib.Path(sys.argv[1]).glob("*.trx"):
    if path.stat().st_size > 16 * 1024 * 1024:
        continue
    root = ET.parse(path).getroot()
    for result in root.findall(".//t:UnitTestResult", namespace):
        if result.get("outcome") != "Failed":
            continue
        node = result.find("t:Output/t:ErrorInfo/t:Message", namespace)
        message = (node.text or "No assertion message") if node is not None else "No assertion message"
        # CI uses only synthetic inputs. Still omit long token/key-like strings from annotations.
        message = re.sub(r"[A-Za-z0-9_+/=-]{40,}", "[redacted]", message[:2000])
        text = result.get("testName", "Unnamed test")[:180] + ": " + message
        text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print("::error title=Native update test failure::" + text)
        count += 1
        if count >= 20:
            break
    if count >= 20:
        break
print("Reported synthetic test failures:", count)
