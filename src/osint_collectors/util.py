"""Small shared helpers."""


def truncate(text: str, limit: int = 200) -> str:
    """Shorten long error text (e.g. nested SSL tracebacks) for reports and consoles."""
    text = str(text)
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."
