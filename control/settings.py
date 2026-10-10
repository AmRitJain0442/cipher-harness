"""Runtime configuration. Secrets are supplied by the operator, never committed."""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / '.env', override=False)

SECURITY = Path(os.getenv('HARNESS_SECURITY_DIR', str(Path.home() / 'security')))
DATA = Path(os.getenv('HARNESS_DATA_DIR', str(Path(__file__).parent / 'data')))
MODEL = os.getenv('HARNESS_MODEL', 'cyberstrike')
MODEL_BASE = os.getenv('HARNESS_MODEL_BASE', 'http://127.0.0.1:8082/v1').rstrip('/')
UPSTREAM_BASE = os.getenv('HARNESS_UPSTREAM_BASE', 'http://127.0.0.1:8080/v1').rstrip('/')
PENTAGI_BASE = os.getenv('HARNESS_PENTAGI_BASE', 'https://127.0.0.1:8443/api/v1').rstrip('/')
TEMPEST_BASE = os.getenv('HARNESS_TEMPEST_BASE', 'http://127.0.0.1:3333').rstrip('/')


def secret(name, fallback=None):
    value = os.getenv(name, '').strip()
    if value:
        return value
    filename = os.getenv(name + '_FILE') or fallback
    if filename and Path(filename).exists():
        return Path(filename).read_text().strip()
    raise RuntimeError(f'Set {name} or {name}_FILE to configure this service.')
