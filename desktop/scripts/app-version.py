"""Resolve one version for the workflow, package metadata and frontend."""
from pathlib import Path
import argparse
import json
import re

parser = argparse.ArgumentParser()
parser.add_argument('--version', default='')
parser.add_argument('--ref', default='')
parser.add_argument('--debug-run', default='')
parser.add_argument('--sha', default='')
args = parser.parse_args()
package = Path(__file__).resolve().parents[1] / 'frontend/package.json'
version = args.version.strip()
if not version and args.ref.startswith('desktop-v'):
    version = args.ref.removeprefix('desktop-v')
if not version:
    version = json.loads(package.read_text())['version']
if args.debug_run:
    assert args.debug_run.isdigit(), 'Invalid debug run number'
    assert re.fullmatch(r'[0-9a-fA-F]{7,40}', args.sha), 'Invalid commit SHA'
    version = f'{version.split("-", 1)[0]}-beta.{args.debug_run}.{args.sha[:7]}'
if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?', version):
    raise SystemExit('Invalid Desktop version; use a version such as 1.4.2 or 1.4.2-beta.1')
print(version)
