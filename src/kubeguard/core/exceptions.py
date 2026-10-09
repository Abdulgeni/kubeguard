"""Exception hierarchy for KubeGuard."""


class KubeGuardError(Exception):
    """Base class for all KubeGuard errors."""


class RuleDefinitionError(KubeGuardError):
    """A Rule subclass is missing required metadata or has invalid metadata."""


class DuplicateRuleError(KubeGuardError):
    """Two different rule classes declare the same rule ID."""


class RuleLoadError(KubeGuardError):
    """A rule module could not be imported during discovery."""


class ScannerError(KubeGuardError):
    """Base class for scanner failures."""


class ImageNotFoundError(ScannerError):
    """The requested image does not exist in the local Docker daemon."""


class DockerUnavailableError(ScannerError):
    """The Docker daemon could not be reached or returned an error."""


class PackageEnumerationError(ScannerError):
    """Installed packages could not be listed for an image."""


class ContainerExecError(ScannerError):
    """A command run inside a container failed or could not start."""

    def __init__(self, message: str, exit_status: int | None = None) -> None:
        super().__init__(message)
        self.exit_status = exit_status


class NvdError(KubeGuardError):
    """An NVD API request failed."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class ConfigError(KubeGuardError):
    """The configuration file is missing, unreadable, or invalid."""