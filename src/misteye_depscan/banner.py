"""MistEye DepScan startup banner."""

from __future__ import annotations

import sys

MISTEYE_BANNER = r"""
                                                  
▄▄▄      ▄▄▄                  ▄▄▄▄▄▄▄             
████▄  ▄████ ▀▀         ██   ███▀▀▀▀▀             
███▀████▀███ ██  ▄█▀▀▀ ▀██▀▀ ███▄▄    ██ ██ ▄█▀█▄ 
███  ▀▀  ███ ██  ▀███▄  ██   ███      ██▄██ ██▄█▀ 
███      ███ ██▄ ▄▄▄█▀  ██   ▀███████  ▀██▀ ▀█▄▄▄ 
                                        ██        
                                      ▀▀▀         
""".strip("\n")


def print_banner(*, stream=None) -> None:
    print(MISTEYE_BANNER, file=stream or sys.stderr)
    print(file=stream or sys.stderr)
