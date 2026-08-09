<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict,
WebDAV-centered subset of the protocol.
-->

# OpenCloudMesh Go Project Governance

Adapted from the [CNCF maintainer governance template](https://github.com/cncf/project-template/blob/main/GOVERNANCE-maintainer.md) and customized for OpenCloudMesh Go.

<!-- template begins here-->

The OpenCloudMesh Go project is dedicated to creating a runnable Open Cloud
Mesh (OCM) peer in Go that implements a strict, WebDAV-centered subset of the
OCM protocol. This governance explains how the project is run.

## Current status

OpenCloudMesh Go is currently a solo-maintainer project. The multi-maintainer
mechanisms below (Maintainer Council, voting, becoming or removing a
maintainer) are written so they are ready when the project grows a second
maintainer; with a single maintainer today, that maintainer holds all decision
and merge authority. Sections that do not yet apply to a solo project are
marked as such rather than removed, so the governance stays honest about the
project's current scale.

* [Values](#values)
* [Maintainers](#maintainers)
* [Becoming a Maintainer](#becoming-a-maintainer)
* [Meetings](#meetings)
* [CNCF Resources](#cncf-resources)
* [Code of Conduct Enforcement](#code-of-conduct)
* [Security Response Team](#security-response-team)
* [Voting](#voting)
* [Modifications](#modifying-this-charter)

## Values

The OpenCloudMesh Go and its leadership embrace the following values:

* Openness: Communication and decision-making happens in the open and is discoverable for future
  reference. As much as possible, all discussions and work take place in public
  forums and open repositories.

* Fairness: All stakeholders have the opportunity to provide feedback and submit
  contributions, which will be considered on their merits.

* Community over Product or Company: Sustaining and growing our community takes
  priority over shipping code or sponsors' organizational goals. Each
  contributor participates in the project as an individual.

* Vendor Neutrality: The project direction and decisions are not controlled by
  any single organization. Maintainer selection, roadmap prioritization, and
  release decisions are made based on project merit, not employer affiliation.

* Inclusivity: We innovate through different perspectives and skill sets, which
  can only be accomplished in a welcoming and respectful environment.

* Participation: Responsibilities within the project are earned through
  participation, and there is a clear path up the contributor ladder into leadership
  positions.

## Maintainers

OpenCloudMesh Go Maintainers have write access to the [project GitHub repository](https://github.com/MahdiBaghbani/opencloudmesh-go).
They can merge their own patches or patches from others. The current maintainers
can be found in [MAINTAINERS.md](./MAINTAINERS.md). Maintainers collectively manage the project's
resources and contributors.

This privilege is granted with some expectation of responsibility: maintainers
are people who care about the OpenCloudMesh Go project and want to help it grow and
improve. A maintainer is not just someone who can make changes, but someone who
has demonstrated their ability to collaborate with the team, get the most
knowledgeable people to review code and docs, contribute high-quality code, and
follow through to fix issues (in code or tests).

A maintainer is a contributor to the project's success and a citizen helping
the project succeed.

The collective team of all Maintainers is known as the Maintainer Council, which
is the governing body for the project.

### Becoming a Maintainer

To become a Maintainer you need to demonstrate the following:

* commitment to the project:
  * participate in discussions, contributions, code and documentation reviews
    for 3 months or more,
  * perform reviews for 5 non-trivial pull requests,
  * contribute 5 non-trivial pull requests and have them merged,
* ability to write quality code and/or documentation,
* ability to collaborate with the team,
* understanding of how the team works (policies, processes for testing and code review, etc),
* understanding of the project's code base and coding and documentation style.
  <!-- add any additional Maintainer requirements here -->

A new Maintainer must be proposed by an existing maintainer by opening an issue on the
[GitHub issue tracker](https://github.com/MahdiBaghbani/opencloudmesh-go/issues). A simple majority vote of existing Maintainers
approves the application. Maintainer nominations will be evaluated without prejudice
to employer or demographics and should consider the organizational diversity of the
maintainer group.

<!-- For projects approaching graduation, consider adding: -->
<!-- The maintainers will avoid nominating new maintainers from any organization -->
<!-- that already employs 50% or more of existing maintainers. -->

Maintainers who are selected will be granted the necessary GitHub rights,
and invited to private maintainer channels as those channels are created.

### Removing a Maintainer

Maintainers may resign at any time if they feel that they will not be able to
continue fulfilling their project duties.

Maintainers may also be removed after being inactive, failure to fulfill their
Maintainer responsibilities, violating the Code of Conduct, or other reasons.
Inactivity is defined as a period of very low or no activity in the project
for 6 months or more, with no definite schedule to return
to full Maintainer activity.

A Maintainer may be removed at any time by a 2/3 vote of the remaining maintainers.

### Emeritus Maintainers

Depending on the reason for removal or resignation, a Maintainer may be converted
to Emeritus status. Emeritus Maintainers are recognized for their past contributions
and may still be consulted on project matters, but do not have voting rights or
merge access. Emeritus Maintainers are listed in [MAINTAINERS.md](./MAINTAINERS.md)
under a separate Emeritus section.

An Emeritus Maintainer may be reinstated to active Maintainer status by a simple
majority vote of existing Maintainers, provided they meet the current Maintainer
requirements and can commit to ongoing participation.

## Meetings

Time zones permitting, Maintainers are expected to participate in the public
developer discussion, which today takes place on the
[GitHub issue tracker](https://github.com/MahdiBaghbani/opencloudmesh-go/issues)
rather than a recurring meeting. There is no scheduled developer or maintainer
meeting at this time; one will be added when the project has regular
contributors who would benefit from it.  

Maintainers will also have closed meetings in order to discuss security reports
or Code of Conduct violations. Such meetings should be scheduled by any
Maintainer on receipt of a security issue or CoC report. All current Maintainers
must be invited to such closed meetings, except for any Maintainer who is
accused of a CoC violation.

## CNCF Resources

OpenCloudMesh Go is not a CNCF project, so the CNCF resource request process
does not apply. Project resources (repository, CI, releases) are
self-managed by the Maintainers. This section is retained from the template
for symmetry and will be filled in if the project ever joins a foundation.

## Code of Conduct

[Code of Conduct](CODE_OF_CONDUCT.md)
violations by community members will be discussed and resolved privately by
the Maintainers, via the contact methods listed in that document. If a
Maintainer is directly involved in a report and a second Maintainer is
available, the other Maintainer handles it; the CNCF Code of Conduct
Committee path does not apply because this is not a CNCF project.

## Security Response Team

The Maintainers will appoint a Security Response Team to handle security reports.
This committee may simply consist of the Maintainer Council themselves. If this
responsibility is delegated, the Maintainers will appoint a team of at least two
contributors to handle it. The Maintainers will review who is assigned to this
at least once a year.

The Security Response Team is responsible for handling all reports of security
holes and breaches according to the [security policy](SECURITY.md).

## Voting

While most business in OpenCloudMesh Go is conducted by "[lazy consensus](https://community.apache.org/committers/lazyConsensus.html)",
periodically the Maintainers may need to vote on specific actions or changes.
A vote can be taken on the [GitHub issue tracker](https://github.com/MahdiBaghbani/opencloudmesh-go/issues),
or privately for security or conduct matters. Any Maintainer may
demand a vote be taken.

Most votes require a simple majority of all Maintainers to succeed, except where
otherwise noted. Two-thirds majority votes mean at least two-thirds of all
existing maintainers.

<!-- For projects with maintainers from multiple organizations, consider adding -->
<!-- an org-balanced voting clause. Projects with org-balanced governance      -->
<!-- demonstrate stronger health indicators for CNCF level transitions.       -->
<!-- Example: "No single organization's employees may cast more than 1/3 of   -->
<!-- the total votes on any decision." -->

## Modifying this Charter

Changes to this Governance and its supporting documents may be approved by
a 2/3 vote of the Maintainers.
