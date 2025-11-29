from tool_detector import detect_all_tools
import logging

logging.basicConfig(level=logging.INFO)

tools = detect_all_tools()
print("\nDetected Tools:")
for tool_id, info in tools.items():
    print(f"- {tool_id}: {info['name']} (Available: {info['available']})")

expected_new_tools = ['enum4linux_classic', 'snmpwalk_v1', 'feroxbuster_https']
missing = [t for t in expected_new_tools if t not in tools]

if missing:
    print(f"\nERROR: Missing tools: {missing}")
    exit(1)
else:
    print("\nSUCCESS: All new tools present.")
