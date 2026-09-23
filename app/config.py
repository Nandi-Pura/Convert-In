from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

MAX_CONFIG_BYTES = 100 * 1024 * 1024
MAX_REQUEST_BYTES = 110 * 1024 * 1024


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FCS_")
    data_dir: Path = Path("data")
    workspace_dir: Path = Path("workspace")
    max_input_bytes: int = MAX_CONFIG_BYTES
    max_request_bytes: int = MAX_REQUEST_BYTES
    pan_lab_validation_enabled: bool = False
    pan_lab_isolated: bool = False
    pan_lab_host: str|None = None
    pan_lab_host_allowlist: str = ""
    pan_lab_ca_bundle: Path|None = None

    @property
    def database_url(self) -> str:
        return f"sqlite:///{self.data_dir / 'studio.db'}"


settings = Settings()