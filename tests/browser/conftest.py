import os,socket,subprocess,sys,tempfile,time
from contextlib import suppress
import pytest

pytest.importorskip("pytest_playwright")

@pytest.fixture(scope="session")
def live_server():
    sock=socket.socket(); sock.bind(("127.0.0.1",0)); port=sock.getsockname()[1]; sock.close(); url=f"http://127.0.0.1:{port}"
    root=tempfile.mkdtemp(prefix="convert-browser-"); env={**os.environ,"FCS_DATA_DIR":root,"FCS_WORKSPACE_DIR":root+"/workspace"}
    subprocess.run([sys.executable,"-m","alembic","upgrade","head"],env=env,check=True,capture_output=True,text=True)
    log_path=os.path.join(root,"server.log"); log=open(log_path,"w+",encoding="utf-8")
    process=subprocess.Popen([sys.executable,"-m","uvicorn","app.main:app","--host","127.0.0.1","--port",str(port)],stdout=log,stderr=subprocess.STDOUT,env=env)
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=.1): break
        except OSError:
            if process.poll() is not None: pytest.fail("Browser test server exited during startup")
            time.sleep(.1)
    else: pytest.fail("Browser test server did not start")
    try: yield url,log_path
    finally:
        process.terminate()
        with suppress(subprocess.TimeoutExpired): process.wait(timeout=5)
        if process.poll() is None:
            process.kill(); process.wait(timeout=5)
        log.close()