from pathlib import Path
import re

def fail(msg):
    raise SystemExit(msg)

def function_bounds(lines, pattern):
    hits = [i for i, line in enumerate(lines) if re.search(pattern, line)]
    if len(hits) != 1:
        fail(f"function match {pattern!r}: {len(hits)}")
    start = hits[0]

    body_open = None
    for i in range(start, min(len(lines), start + 24)):
        if "{" in lines[i]:
            body_open = i
            break
    if body_open is None:
        fail(f"function body start not found for {pattern!r}")

    for i in range(body_open + 1, len(lines)):
        if re.match(r"^}\s*(?:/\*.*\*/\s*)?$", lines[i]):
            return start, i + 1
    fail(f"function body end not found for {pattern!r}")

def unique_index(indices, label):
    if len(indices) != 1:
        fail(f"{label} match count={len(indices)}")
    return indices[0]

def runtime_block_start(lines, start, end, assignment_pattern, label):
    assigns = [
        i for i in range(start, end)
        if re.search(assignment_pattern, lines[i])
    ]
    assign = unique_index(assigns, f"{label} assignment")
    for i in range(assign - 1, max(start - 1, assign - 12), -1):
        if re.match(r"^\s*#\s*ifdef\s+CONFIG_KSU_SUSFS\s*$", lines[i]):
            return i, assign
    fail(f"{label} CONFIG_KSU_SUSFS runtime block start not found")

def move_open(path):
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    original_text = "".join(lines)
    global_calls_before = original_text.count("ksu_handle_faccessat(&")
    if global_calls_before < 2:
        fail(f"open global hook count too small={global_calls_before}")

    fs, fe = function_bounds(
        lines, r"^\s*(?:static\s+)?long\s+do_faccessat\s*\("
    )
    hooks = [
        i for i in range(fs, fe)
        if re.search(r"^\s*ksu_handle_faccessat\s*\(", lines[i])
    ]
    if len(hooks) != 2:
        fail(f"open function hook count={len(hooks)}; expected dual SUSFS/inline branches")

    guards = [
        i for i in range(fs, fe)
        if re.search(r"if\s*\(\s*mode\s*&\s*~S_IRWXO\s*\)", lines[i])
    ]
    guard = unique_index(guards, "open original invalid-mode guard")

    runtime_start, assign = runtime_block_start(
        lines, fs, fe,
        r"^\s*ksu_filename\s*=\s*getname_flags\s*\(",
        "open",
    )
    if not (runtime_start < min(hooks) < guard and assign < guard):
        fail(
            f"open preimage ordering unexpected runtime={runtime_start} "
            f"hooks={hooks} guard={guard}"
        )

    early = [
        "\tif (mode & ~S_IRWXO) /* fast-fail before KSU/SUSFS work */\n",
        "\t\treturn -EINVAL;\n",
        "\n",
    ]
    lines[runtime_start:runtime_start] = early
    text = "".join(lines)

    if text.count("ksu_handle_faccessat(&") != global_calls_before:
        fail("open global hook call count changed")
    path.write_text(text, encoding="utf-8")

    post = text.splitlines()
    fs, fe = function_bounds(
        post, r"^\s*(?:static\s+)?long\s+do_faccessat\s*\("
    )
    hooks2 = [
        i for i in range(fs, fe)
        if re.search(r"^\s*ksu_handle_faccessat\s*\(", post[i])
    ]
    guards2 = [
        i for i in range(fs, fe)
        if re.search(r"if\s*\(\s*mode\s*&\s*~S_IRWXO\s*\)", post[i])
    ]
    if len(hooks2) != 2 or len(guards2) != 2:
        fail(
            f"open postcondition counts hooks={len(hooks2)} guards={len(guards2)}"
        )
    if not guards2[0] < min(hooks2) < guards2[1]:
        fail(
            f"open validation-first order failed guards={guards2} hooks={hooks2}"
        )

def move_stat(path):
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    original_text = "".join(lines)
    global_calls_before = original_text.count("ksu_handle_stat(&")
    if global_calls_before < 2:
        fail(f"stat global hook count too small={global_calls_before}")

    fs, fe = function_bounds(
        lines, r"^\s*(?:static\s+)?int\s+vfs_statx\s*\("
    )
    hooks = [
        i for i in range(fs, fe)
        if re.search(r"^\s*ksu_handle_stat\s*\(", lines[i])
    ]
    if len(hooks) != 2:
        fail(f"stat function hook count={len(hooks)}; expected dual SUSFS/inline branches")

    guards = [
        i for i in range(fs, fe)
        if "flags & ~(" in lines[i]
    ]
    guard = unique_index(guards, "stat original invalid-flags guard")

    runtime_start, assign = runtime_block_start(
        lines, fs, fe,
        r"^\s*ksu_filename\s*=\s*getname_flags\s*\(",
        "stat",
    )
    if not (runtime_start < min(hooks) < guard and assign < guard):
        fail(
            f"stat preimage ordering unexpected runtime={runtime_start} "
            f"hooks={hooks} guard={guard}"
        )

    early = [
        "\tif ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |\n",
        "\t\t       AT_EMPTY_PATH | KSTAT_QUERY_FLAGS)) != 0)\n",
        "\t\treturn -EINVAL;\n",
        "\n",
    ]
    lines[runtime_start:runtime_start] = early
    text = "".join(lines)

    if text.count("ksu_handle_stat(&") != global_calls_before:
        fail("stat global hook call count changed")
    path.write_text(text, encoding="utf-8")

    post = text.splitlines()
    fs, fe = function_bounds(
        post, r"^\s*(?:static\s+)?int\s+vfs_statx\s*\("
    )
    hooks2 = [
        i for i in range(fs, fe)
        if re.search(r"^\s*ksu_handle_stat\s*\(", post[i])
    ]
    guards2 = [
        i for i in range(fs, fe)
        if "flags & ~(" in post[i]
    ]
    if len(hooks2) != 2 or len(guards2) != 2:
        fail(
            f"stat postcondition counts hooks={len(hooks2)} guards={len(guards2)}"
        )
    if not guards2[0] < min(hooks2) < guards2[1]:
        fail(
            f"stat validation-first order failed guards={guards2} hooks={hooks2}"
        )

move_open(Path("kernel/fs/open.c"))
move_stat(Path("kernel/fs/stat.c"))
print("U7_N4_OPEN_VALIDATION_FIRST=PASS")
print("U7_N4_STAT_VALIDATION_FIRST=PASS")
print("U7_N4_DUAL_BRANCH_PREIMAGE=PASS")
