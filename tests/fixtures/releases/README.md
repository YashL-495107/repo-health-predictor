# Recorded registry responses (trimmed)

Recorded live on 2026-11-07 from pypi.org and registry.npmjs.org, trimmed to the fields releases.py uses, for
offline parser tests. Files:

- pypi_idna_project.json: /pypi/idna/json (5 latest releases)
- pypi_requests_2.31.0_version.json: /pypi/requests/2.31.0/json (info.requires_dist)
- pypi_idna_provenance.json: PEP 740 /integrity/idna/<v>/<file>/provenance (publisher only)
- pypi_provenance_404.json: the 404 body for a release without provenance
- npm_left-pad_packument.json: registry.npmjs.org/left-pad (4 latest versions)

Synthetic release pairs used by the detector tests are built in the tests themselves from inert text.
