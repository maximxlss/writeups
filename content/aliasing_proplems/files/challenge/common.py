from subprocess import Popen, check_call
import tempfile
import shutil


def build(payload: bytes = None) -> bytes:
    with tempfile.TemporaryDirectory() as temp_dir:
        shutil.copytree("/src", temp_dir, dirs_exist_ok=True)
        if payload is not None:
            with open(f"{temp_dir}/payload/src/payload.rs", "wb") as f:
                f.write(payload)
        p = Popen(["nsjail", "--config", "cargo_nsjail.cfg", "-B", f"{temp_dir}:/tmp", "--", "/bin/bash", "-c", "cd /tmp && cargo build"])
        p.wait()
        with open(f"{temp_dir}/target/debug/runtime", "rb") as f:
            output = f.read()
    return output

def run(binary: bytes):
    with tempfile.TemporaryDirectory() as temp_dir:
        with open(f"{temp_dir}/runtime", "wb") as f:
            f.write(binary)
        check_call(["chmod", "+x", f"{temp_dir}/runtime"])
        p = Popen(["nsjail", "--config", "exec_nsjail.cfg", "-B", f"{temp_dir}:/tmp", "--", "/tmp/runtime"])
        p.wait()
        print(f"Exit code: {p.returncode}")
