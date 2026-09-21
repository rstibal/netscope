"""
Renders netscope.ico from the same glyph netscope_tray.make_icon() draws for
the running tray icon, so the .exe file icon and the tray icon are always the
same artwork instead of two things someone has to remember to keep in sync.

Run after changing make_icon()'s palette or glyph:

    python make_appicon.py
"""
from netscope_tray import make_icon

SIZES = [16, 24, 32, 48, 64, 128, 256]

if __name__ == "__main__":
    imgs = [make_icon("idle", s) for s in SIZES]
    imgs[-1].save("netscope.ico", format="ICO",
                  sizes=[(s, s) for s in SIZES], append_images=imgs[:-1])
    print("wrote netscope.ico")
