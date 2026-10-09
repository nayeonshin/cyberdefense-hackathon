"""Put a secret from the clipboard into .env without showing it.

    python -m actor.setenv CLICKHOUSE_PASSWORD

Copy the value first (for example with the copy button next to a new password), then run
this. Only the length is printed.
"""
import sys
import tkinter

from .config import ROOT


def main() -> None:
    if len(sys.argv) != 2 or not sys.argv[1].replace("_", "").isalnum():
        sys.exit("usage: python -m actor.setenv NAME")
    name = sys.argv[1]
    window = tkinter.Tk()
    window.withdraw()
    try:
        value = window.clipboard_get().strip()
    except tkinter.TclError:
        sys.exit("the clipboard is empty")
    finally:
        window.destroy()
    if not value or "\n" in value:
        sys.exit("the clipboard does not hold a single-line value")

    path = ROOT / ".env"
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    for i, line in enumerate(lines):
        if line.startswith(name + "="):
            lines[i] = f"{name}={value}"
            break
    else:
        lines.append(f"{name}={value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{name} set ({len(value)} characters)")


if __name__ == "__main__":
    main()
