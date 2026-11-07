"""Code-quality counts for the report: docstrings, comments and UI function comments.

Run on machine A: python evidence/comment_count.py   (writes evidence/out/comment_count.*)
"""

from __future__ import annotations

import ast
import io
import re
import sys
import tokenize

from _common import ROOT, Report

VIETNAMESE = re.compile(
    "[ăâđêôơưáàảãạấầẩẫậắằẳẵặéèẻẽẹếềểễệíìỉĩịóòỏõọốồổỗộớờởỡợúùủũụứừửữựýỳỷỹỵ]", re.IGNORECASE
)


def main() -> int:
    """Đếm trên các module Python ở thư mục gốc và hàm cấp cao nhất trong ui/app.js."""
    report = Report("comment_count", "source")
    modules = sorted(ROOT.glob("*.py"))
    functions = documented = comments = vietnamese = 0
    missing = []
    for path in modules:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        if not ast.get_docstring(tree):
            missing.append(f"{path.name} (module)")
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions += 1
                if ast.get_docstring(node):
                    documented += 1
                else:
                    missing.append(f"{path.name}:{node.lineno} {node.name}")
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                comments += 1
                vietnamese += bool(VIETNAMESE.search(token.string))
    report.line(f"Python modules at the project root: {len(modules)}")
    report.line(f"functions and methods: {functions}, with a docstring: {documented}")
    report.line(f"comments: {comments}, of which in Vietnamese: {vietnamese}")
    report.line(f"without docstring: {missing or 'none'}")

    lines = (ROOT / "ui" / "app.js").read_text(encoding="utf-8").splitlines()
    pattern = re.compile(r"^(async )?function |^const [A-Za-z_]+ = (async )?\(")
    top = [index for index, line in enumerate(lines) if pattern.match(line)]
    commented = sum(
        index > 0
        and lines[index - 1].strip().endswith(("*/",))
        or lines[index - 1].strip().startswith("//")
        for index in top
    )
    report.line(f"ui/app.js top-level functions: {len(top)}, with a comment above: {commented}")
    report.data.update(
        modules=len(modules),
        functions=functions,
        documented=documented,
        comments=comments,
        comments_vietnamese=vietnamese,
        js_functions=len(top),
        js_commented=commented,
    )
    report.check(documented == functions and commented == len(top), "every function documented")
    return report.save()


if __name__ == "__main__":
    sys.exit(main())
