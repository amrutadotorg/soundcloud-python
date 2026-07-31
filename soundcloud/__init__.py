"""Python Soundcloud API Wrapper."""

__version__ = "2.0.0"
__all__ = ["Client"]

USER_AGENT = f"SoundCloud Python API Wrapper {__version__}"

from soundcloud.client import Client
