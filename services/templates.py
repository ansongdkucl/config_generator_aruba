# services/templates.py

from pathlib import Path

class TemplateManager:
    """Loads Jinja-style templates stored in templates/*.j2."""

    def __init__(self, template_dir: Path):
        self.template_dir = template_dir

        # Map display label → template filename stem
        self.mapping = {
            "4100i - Standard": "4100i_standard",
            "4100i - Audio Visual": "4100i_av",
            "6300m - Standard": "6300m_standard",
            "6300m - Audio Visual": "6300m_av",
        }

    def list_templates(self):
        return list(self.mapping.keys())

    def load_template(self, template_label: str) -> str:
        stem = self.mapping.get(template_label, template_label)
        path = self.template_dir / f"{stem}.j2"
        if not path.exists():
            raise FileNotFoundError(f"Template not found: {path}")
        return path.read_text(encoding="utf-8")
