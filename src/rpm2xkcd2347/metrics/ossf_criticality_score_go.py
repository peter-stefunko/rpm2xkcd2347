import json
import os
import shutil
import subprocess
import time
from collections import defaultdict
from pathlib import Path

from ..graph.model import DependencyGraph
from .base import MetricsProvider
from .model import PackageMetrics, RepositorySignals
from .resolve import anitya


class OssfCriticalityScoreGoProvider(MetricsProvider):
    def fetch(self, graph: DependencyGraph) -> dict[str, PackageMetrics]:
        binary = self._find_binary()
        if not binary:
            raise RuntimeError(
                'criticality_score binary not found; '
                'install with: go install github.com/ossf/criticality_score/v2/cmd/criticality_score@latest'
            )
        token = os.environ.get('GITHUB_AUTH_TOKEN')
        if not token:
            raise RuntimeError('GITHUB_AUTH_TOKEN environment variable not set')

        repo_to_ids = self._resolve_repo_urls(graph)

        result: dict[str, PackageMetrics] = {}
        for repo_url, spdx_ids in repo_to_ids.items():
            metrics = self._score_repo(binary, token, repo_url)
            if metrics is None:
                continue
            for spdx_id in spdx_ids:
                result[spdx_id] = metrics

        return result

    def _resolve_repo_urls(self, graph: DependencyGraph) -> dict[str, list[str]]:
        src_to_ids: dict[str, list[str]] = defaultdict(list)
        for spdx_id, pkg in graph.packages.items():
            if not pkg.purl:
                continue
            src = anitya.extract_src_name(pkg.purl)
            if src:
                src_to_ids[src].append(spdx_id)

        repo_to_ids: dict[str, list[str]] = defaultdict(list)
        for src_name, spdx_ids in src_to_ids.items():
            repo = anitya.lookup_github_repo(src_name)
            if repo:
                repo_to_ids[f'https://github.com/{repo}'].extend(spdx_ids)
            time.sleep(0.5)

        return repo_to_ids

    def _score_repo(self, binary: str, token: str, repo_url: str) -> PackageMetrics | None:
        try:
            proc = subprocess.run(
                [binary, '-format', 'json', '-depsdev-disable', repo_url],
                capture_output=True,
                text=True,
                env={**os.environ, 'GITHUB_AUTH_TOKEN': token},
                timeout=120,
            )
            lines = [l for l in proc.stdout.splitlines() if l.strip().startswith('{')]
            if not lines:
                print(f'  [no output for {repo_url}]')
                return None
            data = json.loads(lines[-1])
            score_str = data.get('default_score') or data.get('scoring_score')
            score = float(score_str) if score_str is not None else None
            return PackageMetrics(signals=self._parse_signals(data), criticality_score=score)
        except Exception as e:
            print(f'  [failed for {repo_url}]: {e}')
            return None

    def _find_binary(self) -> str | None:
        candidate = Path.home() / 'go' / 'bin' / 'criticality_score'
        if candidate.exists():
            return str(candidate)
        return shutil.which('criticality_score')

    def _parse_signals(self, data: dict) -> RepositorySignals:
        repo = data.get('repo', {})
        legacy = data.get('legacy', {})
        return RepositorySignals(
            repo_url=repo.get('url', ''),
            created_since=legacy.get('created_since'),
            updated_since=legacy.get('updated_since'),
            contributor_count=legacy.get('contributor_count'),
            org_count=legacy.get('org_count'),
            commit_frequency=legacy.get('commit_frequency'),
            recent_release_count=legacy.get('recent_release_count'),
            updated_issues_count=legacy.get('updated_issues_count'),
            closed_issues_count=legacy.get('closed_issues_count'),
            issue_comment_frequency=legacy.get('issue_comment_frequency'),
            star_count=repo.get('star_count'),
            language=repo.get('language') or None,
            license=repo.get('license') or None,
        )
