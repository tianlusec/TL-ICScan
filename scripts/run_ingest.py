import subprocess
import os
import sys
import argparse
from subprocess import TimeoutExpired

env = os.environ.copy()
env["PYTHONIOENCODING"] = "utf-8"

python_exe = sys.executable

script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, ".."))

rust_bin = os.path.join(project_root, "tianlu-intel-core", "target", "release", "tianlu-intel-core")
if os.name == 'nt':
    rust_bin += ".exe"

if not os.path.exists(rust_bin):
    alt = os.path.join(project_root, "tianlu-intel-core.exe")
    if os.path.exists(alt):
        rust_bin = alt
    else:
        print(f"Error: Rust binary not found at {rust_bin}. Please build it first.")
        sys.exit(2)

db_path = os.path.join(project_root, "tianlu_intel_v2.db")

parser = argparse.ArgumentParser(description="Run a collector module and ingest its output")
parser.add_argument("--module", default="tianlu_intel_collectors.exploit_db", help="Python collector module to run (e.g. tianlu_intel_collectors.nvd)")
parser.add_argument("--source", default="exploit_db", help="Source name to pass to ingest (e.g. exploit_db)")
args = parser.parse_args()

cmd1 = [python_exe, "-m", args.module]

cmd2 = [rust_bin, "ingest", "--source", args.source, "--db", db_path]

print(f"Starting ingestion for module={args.module} source={args.source}...")
try:
    p1 = subprocess.Popen(cmd1, stdout=subprocess.PIPE, env=env, cwd=project_root)
    
    # Check if p1 started successfully
    if p1.poll() is not None:
        print(f"Error: Collector process exited immediately with code {p1.returncode}")
        sys.exit(1)

    p2 = subprocess.Popen(cmd2, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=project_root)
    p1.stdout.close()
    try:
        output, error = p2.communicate(timeout=120)
    except TimeoutExpired:
        print("Error: Ingestion timed out. Killing processes.")
        p2.kill()
        p1.kill()
        output, error = p2.communicate()
    finally:
        # Ensure processes are terminated
        if p1.poll() is None: p1.kill()
        if p2.poll() is None: p2.kill()

    try:
        p1.wait(timeout=5)
    except TimeoutExpired:
        p1.kill()

    if output:
        try:
            print("Output:", output.decode())
        except Exception:
            print("Output: <binary or non-decodable>")
    if error:
        try:
            print("Error:", error.decode())
        except Exception:
            print("Error: <binary or non-decodable>")

    print(f"Return code: {p2.returncode}")
    if p2.returncode != 0:
        sys.exit(p2.returncode)
except Exception as e:
    print(f"Exception: {e}")
    sys.exit(1)
