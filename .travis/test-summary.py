# Prints per-module and overall test totals from the Surefire/Failsafe XML reports,
# naming every skipped test with its reason, so the CI log states what ran and passed.
import glob
import os
import xml.etree.ElementTree as ET

totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
per_module = {}
skipped = []
for path in sorted(glob.glob("**/target/*-reports/TEST-*.xml", recursive=True)):
    module = path.split("/target/")[0]
    kind = os.path.basename(os.path.dirname(path))
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    for suite in suites:
        key = module + " (" + kind + ")"
        counts = per_module.setdefault(key, {"tests": 0, "failures": 0, "errors": 0, "skipped": 0})
        for k in totals:
            v = int(float(suite.get(k, "0") or 0))
            counts[k] += v
            totals[k] += v
        for case in suite.iter("testcase"):
            sk = case.find("skipped")
            if sk is not None:
                skipped.append("%s.%s: %s" % (case.get("classname"), case.get("name"), sk.get("message") or (sk.text or "").strip() or "no message"))

print("================ Test results (Surefire/Failsafe reports) ================")
for key in sorted(per_module):
    c = per_module[key]
    print("%-60s run=%d failures=%d errors=%d skipped=%d" % (key, c["tests"], c["failures"], c["errors"], c["skipped"]))
if skipped:
    print("Skipped tests (%d):" % len(skipped))
    for s in skipped:
        print("  SKIPPED " + s)
passed = totals["tests"] - totals["failures"] - totals["errors"] - totals["skipped"]
print("TOTAL: tests run=%d, passed=%d, failures=%d, errors=%d, skipped=%d" % (
    totals["tests"], passed, totals["failures"], totals["errors"], totals["skipped"]))
print("SEAL TEST SUMMARY COMPLETE")
