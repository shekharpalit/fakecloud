import base64, contextlib, io, json, os, subprocess, sys, time, traceback

channel = os.fdopen(os.dup(1), "w", buffering=1)
os.dup2(2, 1)
scope = {"__name__": "__main__"}


def text(value):
    return [{"type": "text", "text": value}]


def run_code(arguments):
    global scope
    if arguments.get("language", "python") != "python":
        return {"content": text("This sandbox runs Python only."), "isError": True}
    if arguments.get("clearContext"):
        scope = {"__name__": "__main__"}
    out, err, code, started = io.StringIO(), io.StringIO(), 0, time.monotonic()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            exec(compile(arguments.get("code", ""), "<code>", "exec"), scope)
        except SystemExit as stop:
            code = stop.code if isinstance(stop.code, int) else 1
        except BaseException:
            traceback.print_exc()
            code = 1
    stdout, stderr = out.getvalue(), err.getvalue()
    return {"content": text(stdout + stderr), "isError": code != 0,
            "structuredContent": {"stdout": stdout, "stderr": stderr, "exitCode": code,
                                  "executionTime": round(time.monotonic() - started, 3)}}


def run_command(arguments):
    started = time.monotonic()
    done = subprocess.run(arguments.get("command", ""), shell=True, capture_output=True, text=True, timeout=600)
    return {"content": text(done.stdout + done.stderr), "isError": done.returncode != 0,
            "structuredContent": {"stdout": done.stdout, "stderr": done.stderr, "exitCode": done.returncode,
                                  "executionTime": round(time.monotonic() - started, 3)}}


def write_files(arguments):
    files = arguments.get("content", [])
    for item in files:
        path = item["path"]
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if "blob" in item:
            with open(path, "wb") as handle:
                handle.write(base64.b64decode(item["blob"]))
        else:
            with open(path, "w") as handle:
                handle.write(item.get("text", ""))
    return {"content": text(f"Successfully wrote all {len(files)} files"), "isError": False}


def read_files(arguments):
    content = []
    for path in arguments.get("paths", [arguments.get("path")]):
        with open(path, "rb") as handle:
            data = handle.read()
        try:
            resource = {"type": "text", "uri": f"file://{os.path.abspath(path)}", "text": data.decode()}
        except UnicodeDecodeError:
            resource = {"type": "blob", "uri": f"file://{os.path.abspath(path)}", "blob": base64.b64encode(data).decode()}
        content.append({"type": "resource", "resource": resource})
    return {"content": content, "isError": False}


def list_files(arguments):
    directory = arguments.get("directoryPath") or "."
    content = [{"type": "resource_link", "name": name, "uri": f"file://{os.path.abspath(os.path.join(directory, name))}",
                "size": os.path.getsize(os.path.join(directory, name))} for name in sorted(os.listdir(directory))]
    return {"content": content, "isError": False}


def remove_files(arguments):
    for path in arguments.get("paths", []):
        os.remove(path)
    return {"content": text("Files removed"), "isError": False}


METHODS = {"executeCode": run_code, "executeCommand": run_command, "writeFiles": write_files,
           "readFiles": read_files, "listFiles": list_files, "removeFiles": remove_files}

for line in sys.stdin:
    request = json.loads(line)
    method = METHODS.get(request.get("name"))
    try:
        answer = method(request.get("arguments") or {}) if method else {
            "content": text(f"Unknown tool {request.get('name')}"), "isError": True}
    except Exception as error:
        answer = {"content": text(f"{type(error).__name__}: {error}"), "isError": True}
    channel.write(json.dumps(answer) + "\n")
