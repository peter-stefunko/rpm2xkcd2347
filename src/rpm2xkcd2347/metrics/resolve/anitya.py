import re
import requests
import time


def extract_src_name(purl: str) -> str | None:
    """Extract the source RPM package name from an RPM PURL's upstream= qualifier."""
    m = re.search(r'upstream=([^&]+)\.src\.rpm', purl)
    if not m:
        return None
    parts = m.group(1).split('-')
    name_parts = []
    for part in parts:
        if part[0].isdigit():
            break
        name_parts.append(part)
    return '-'.join(name_parts) or None


def lookup_project(src_name: str) -> dict | None:
    """Return the Anitya project dict for a Fedora src RPM name, or None.

    Makes two Anitya API calls: the packages endpoint to confirm the Fedora
    entry and obtain the upstream ecosystem URL, then the projects endpoint to
    get the matching project. The returned dict contains fields such as
    'backend' and 'version_url' that callers can use to extract backend-specific
    information.
    """
    pkg_data = _get(
        "https://release-monitoring.org/api/v2/packages/",
        params={'name': src_name, 'ecosystem': 'Fedora'},
    )
    if not pkg_data or not pkg_data.get('items'):
        return None
    item = pkg_data['items'][0]
    ecosystem_url = item.get('ecosystem', '')
    project_name = item.get('project', src_name)

    time.sleep(0.25)

    proj_data = _get(
        "https://release-monitoring.org/api/v2/projects/",
        params={'name': project_name},
    )
    if not proj_data:
        return None
    return next(
        (p for p in proj_data.get('items', []) if p.get('ecosystem') == ecosystem_url),
        None,
    )


def lookup_github_repo(src_name: str) -> str | None:
    """Return the GitHub owner/repo for a Fedora src RPM name via Anitya, or None."""
    project = lookup_project(src_name)
    if project is None or project.get('backend') != 'GitHub':
        return None
    return project.get('version_url')  # "owner/repo"


def _get(url: str, params: dict | None = None) -> dict | None:
    try:
        r = requests.get(url, params=params, headers={'User-Agent': 'rpm2xkcd2347/0.1'}, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None
