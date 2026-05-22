from __future__ import annotations

import os
import stat
from getpass import getpass
from pathlib import Path

API_DOCS_URL = "https://app.misteye.io/api-docs"
API_KEYS_URL = "https://app.misteye.io/api-keys"
DEFAULT_CONFIG_DIR = Path.home() / ".config" / "misteye"
API_KEY_FILENAME = "api_key"


def config_dir() -> Path:
    override = os.environ.get("MISTEYE_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    return DEFAULT_CONFIG_DIR


def api_key_path() -> Path:
    return config_dir() / API_KEY_FILENAME


def _check_file_permissions(path: Path) -> None:
    if not path.exists():
        return
    mode = path.stat().st_mode
    if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
        raise PermissionError(
            f"API key file {path} must be readable/writable only by the current user (chmod 600)."
        )


def load_api_key(*, interactive: bool = False) -> str | None:
    env_key = os.environ.get("MISTEYE_API_KEY", "").strip()
    if env_key:
        return env_key

    path = api_key_path()
    if path.exists():
        _check_file_permissions(path)
        key = path.read_text(encoding="utf-8").strip()
        if key:
            return key

    if interactive:
        return prompt_and_save_api_key()
    return None


def save_api_key(key: str) -> Path:
    key = key.strip()
    if not key:
        raise ValueError("API key cannot be empty.")

    directory = config_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = api_key_path()
    path.write_text(key, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return path


def prompt_and_save_api_key() -> str:
    print("MistEye API key is required.")
    print(f"Get a free key at: {API_KEYS_URL}")
    key = getpass("Enter MISTEYE_API_KEY: ").strip()
    if not key:
        raise SystemExit("No API key provided.")
    path = save_api_key(key)
    print(f"Saved API key to {path} (chmod 600).")
    return key


def ensure_api_key(*, interactive: bool = True) -> str:
    key = load_api_key(interactive=interactive)
    if not key:
        print("Missing MISTEYE_API_KEY.")
        print(f"Set env var MISTEYE_API_KEY or create {api_key_path()} (chmod 600).")
        print(f"Get a key at: {API_KEYS_URL}")
        raise SystemExit(3)
    return key
