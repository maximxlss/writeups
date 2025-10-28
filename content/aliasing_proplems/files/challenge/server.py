from common import build, run
import base64

payload = base64.b64decode(input())
binary = build(payload)
run(binary)
