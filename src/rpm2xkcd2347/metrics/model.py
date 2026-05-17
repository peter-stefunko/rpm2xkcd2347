from dataclasses import dataclass


@dataclass
class RepositorySignals:
    repo_url: str
    created_since: int | None = None           # months since repo creation on GitHub
    updated_since: int | None = None           # months since last commit on default branch
    contributor_count: int | None = None       # total contributors (capped at 5000)
    org_count: int | None = None               # unique companies among top 15 contributors
    commit_frequency: float | None = None      # commits per week over the last 52 weeks
    recent_release_count: int | None = None    # total release tags
    updated_issues_count: int | None = None    # issues/PRs updated in the last 90 days
    closed_issues_count: int | None = None     # issues/PRs closed in the last 90 days
    issue_comment_frequency: float | None = None  # avg comments per issue in the last 90 days
    star_count: int | None = None
    language: str | None = None
    license: str | None = None


@dataclass
class PackageMetrics:
    signals: RepositorySignals | None = None
    criticality_score: float | None = None
