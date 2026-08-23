# Repository signals

## What is a repository signal?

A **repository signal** is a single, objectively measurable property of a software project that can be read from its source repository and the platform hosting it (commit history, releases, issue tracker, contributor list, packaging metadata).

Signals become useful as **proxies**: a project that has not received a commit in four years and has one contributor is **probably** a riskier building block than one with a hundred active contributors, even though neither number measures risk directly. Several signals are normalized and combined into a single **criticality score**, and that score drives the visual representation in the generated diagram.

We can classify 2 signal properties:

- **Direction.** Some signals point towards criticality when they are *high* (e.g. how many packages depend on the project), others when they are *low* (e.g. the number of contributors).

- **Proxy quality.** Signals are cheap to collect but imperfect. A tiny, finished, one-file library can be both perfectly healthy and completely abandoned-looking; a huge stars count can be a popularity artifact with no bearing on maintenance.

## The signals

### 1. Stars count

The number of users who have starred (bookmarked) the repository on its hosting platform, used as a rough measure of visibility and popularity. It reflects attention rather than usage, and it only accumulates over time — a project cannot lose stars when it stops being maintained.

**Example:** `curl/curl` has tens of thousands of stars, while `util-linux/util-linux` — installed on essentially every Linux system — has a small fraction of that.

### 2. Commit frequency

The average number of commits to the default branch over a recent window, typically expressed as commits per week over the last year. It indicates how much active development the project currently receives.

**Example:** the Linux kernel averages thousands of commits per week; a stable compression library such as `zlib` may average less than one, without that being a problem.

### 3. Time since last commit

How long ago the most recent commit landed on the default branch, usually measured in months. It is the most direct indication of whether anyone is still working on the project and whether a bug report filed today would realistically be answered.

**Example:** a repository whose last commit is from 2016 is unlikely to receive a fix for a newly disclosed CVE without someone stepping in first.

### 4. Time since first commit

The age of the project, measured from its first commit to now. Older projects have had more time to stabilize, accumulate users and be reviewed, so age is generally read as a sign of maturity rather than of risk.

**Example:** `OpenSSL` (first released in 1998) versus a dependency created three months ago — the latter has no track record, the former has a long one.

### 5. Time since last release

How long ago the project published its most recent tagged release or version. It captures whether maintenance actually reaches downstream consumers: a project can keep committing to the main branch while distributions and package managers remain stuck on a years-old release.

**Example:** a library with active commits but no release since 2019 forces packagers to choose between an outdated tarball and shipping an unreleased snapshot.

### 6. Total contributors count

The number of distinct people who have ever contributed commits to the repository. It approximates the size of the pool of people who have some familiarity with the codebase.

**Example:** `systemd` has thousands of lifetime contributors; a typical single-purpose Python dependency on PyPI often has fewer than ten.

### 7. Last year's contributors count

The number of distinct people who contributed within the last twelve months. Unlike the lifetime count, this measures the currently available maintenance capacity, and it drops as soon as a project loses its team.

**Example:** a project with 400 lifetime contributors but 2 in the last year has effectively shrunk to a two-person project, regardless of its history.

### 8. Bus factor

The number of people who would have to be lost (the proverbial "hit by a bus") before the project stalls, usually approximated as the smallest group of contributors responsible for the majority of the code or commits.

**Example:** `xz` was effectively maintained by one exhausted volunteer, which is precisely the opening that the 2024 `xz-utils` backdoor exploited.

### 9. Organizational backing

Whether identifiable organizations — companies, foundations, universities — stand behind the project, usually detected from the employer affiliations of the top contributors or from foundation membership. Backing implies that maintenance is somebody's paid responsibility rather than spare-time work.

**Example:** `Kubernetes` (CNCF, with contributors employed by many vendors) versus a widely used utility maintained by one person in their free time.

### 10. Receives funding

Whether the project has an actual funding stream — sponsorships, grants, a foundation budget, a support contract, or a commercial entity behind it. Funding turns maintenance into work that can be scheduled and sustained, including parts such as security response.

**Example:** OpenSSL was a near-unfunded project when Heartbleed hit in 2014; the resulting Core Infrastructure Initiative funding is an example case for this signal.

### 11. Closed/opened issues ratio

The ratio between issues closed and opened over a recent window, describing whether the project keeps up with its incoming work. A ratio close to or above 1 suggests the tracker is being processed, while a persistently low ratio suggests a growing backlog and unaddressed reports.

**Example:** a project closing 90 of 100 issues opened last quarter is responsive; one closing 5 of 200 has a tracker that is effectively a write-only inbox.

### 12. High dependencies count

The project depends on **many** other packages. A large dependency set means the project inherits the risk, maintenance burden and attack surface of everything below it, and any one of those components can break or compromise it.

**Example:** an application pulling in 400 transitive packages can be broken by a single removed or compromised leaf dependency, as the `left-pad` incident demonstrated.

### 13. Low dependencies count

The project depends on **few** other packages, or none at all. Such a project is self-contained and carries little inherited risk, but it also tends to sit deep in the stack where many other things depend on it.

**Example:** `zlib` has essentially no dependencies of its own, yet sits underneath a large part of the system.
