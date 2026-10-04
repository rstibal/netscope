import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_alerts as A

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

n = A.DesktopNotifier(enabled=True)
# Quote characters PowerShell treats as a string delimiter, straight and curly.
hostile = ["x'; calc; '", "x’; calc; ’", "x‘;calc;‛", "x‚;calc",
           "x\"; calc; \"", "$(calc)", "`n", "a\nb"]
for h in hostile:
    argv, env = n._command("title " + h, "body " + h)
    check("script is the same constant for %r" % ascii(h), argv[-1] == A.DesktopNotifier.SCRIPT)
    check("text never appears in the script for %s" % ascii(h),
          h not in argv[-1] and h not in " ".join(argv))
    check("text arrives intact in the environment for %s" % ascii(h),
          env["NS_TOAST_TITLE"] == "title " + h and env["NS_TOAST_BODY"] == "body " + h)

argv, env = n._command("t" * 500, "m" * 500)
check("long text is cut", len(env["NS_TOAST_TITLE"]) == 200 and len(env["NS_TOAST_BODY"]) == 200)
check("the script reads the environment, not literals",
      "$env:NS_TOAST_TITLE" in A.DesktopNotifier.SCRIPT
      and A.DesktopNotifier.APPID in A.DesktopNotifier.SCRIPT)

sys.exit(1 if fails else 0)
