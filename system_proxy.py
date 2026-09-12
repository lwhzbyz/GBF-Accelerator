"""Restore only the exact PAC value written by this running instance."""
import atexit
import ctypes
import sys
import urllib.parse

if sys.platform == "win32":
    import winreg

INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_original_pac = None  # (value, registry type), None means the value did not exist.
_installed_pac_url = None


def notify_wininet():
    if sys.platform == "win32":
        try:
            for option in (39, 37):
                ctypes.windll.wininet.InternetSetOptionW(0, option, 0, 0)
        except OSError:
            pass


def _read_pac():
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_READ) as key:
        try:
            return winreg.QueryValueEx(key, "AutoConfigURL")
        except FileNotFoundError:
            return None


def get_current_pac_url():
    if sys.platform != "win32":
        return None
    try:
        current = _read_pac()
        return current[0] if current else None
    except OSError:
        return None


def is_pac_proxy_enabled(port=None):
    expected = _installed_pac_url if port is None else f"http://127.0.0.1:{int(port)}/proxy.pac"
    return bool(expected and get_current_pac_url() == expected)


def enable_pac_proxy(pac_url="http://127.0.0.1:8124/proxy.pac"):
    global _original_pac, _installed_pac_url
    if sys.platform != "win32":
        return False
    parsed = urllib.parse.urlsplit(pac_url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.path != "/proxy.pac" or parsed.query or parsed.fragment:
        return False
    try:
        current = _read_pac()
        # An external edit ends our ownership; a later enable starts a new roundtrip.
        previous = _original_pac if _installed_pac_url and current and current[0] == _installed_pac_url else current
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)
        _original_pac, _installed_pac_url = previous, pac_url
        notify_wininet()
        return True
    except OSError:
        return False


def disable_pac_proxy():
    global _original_pac, _installed_pac_url
    if sys.platform != "win32" or _installed_pac_url is None:
        return True
    try:
        current = _read_pac()
        if current and current[0] == _installed_pac_url:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                if _original_pac is None:
                    winreg.DeleteValue(key, "AutoConfigURL")
                else:
                    winreg.SetValueEx(key, "AutoConfigURL", 0, _original_pac[1], _original_pac[0])
            notify_wininet()
        _original_pac = _installed_pac_url = None
        return True
    except OSError:
        return False


atexit.register(disable_pac_proxy)
