# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]
### Added
- Lesson metadata and cards.

### Fixed
- Unintended attack surfaces.

## [0.1.0] - 2021-11-10
### Added
- Attack vector for clickjacking.
- Attack vector for CSRF.
- Email address for users.
- New HTML templates and forms.
- Build arguments for Docker builds.
- Default credentials.
- Backdoor as custom HTTP method.
- Support for configuration via `ENV` variables.
- Optional `--risk` argument.
- Default credentials.
- More descriptive logging.
- Support for HTTPS transport.

### Fixed
- Path argument of session cookie.
- Favicon path.

### Changed
- Error handling for SQLi.
- Default CSP.
- Version reporting.
- Docker base image.

[Unreleased]: https://github.com/sgabe/DSVPWA/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sgabe/DSVPWA/releases/tag/v0.1.0