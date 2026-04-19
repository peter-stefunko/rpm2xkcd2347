from dataclasses import dataclass


@dataclass
class PackageMetrics:
    stars: int | None = None
    contributors: int | None = None
    open_issues: int | None = None
    last_commit_days_ago: int | None = None
    has_funding: bool | None = None
    repo_url: str | None = None
