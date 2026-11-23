"""The pages of the desktop app."""

from .base import BasePage
from .dashboard import DashboardPage
from .database import DatabasePage
from .logs import LogsPage
from .monitoring import MonitoringPage
from .outputs import OutputsPage
from .protection import AUTO_QUARANTINE_CHOICES, ProtectionPage
from .reports import ReportsPage
from .scan import ScanPage
from .settings import SettingsPage, detect_autostart

__all__ = ["BasePage", "DashboardPage", "DatabasePage", "LogsPage", "MonitoringPage",
           "OutputsPage", "ProtectionPage",
           "ReportsPage", "ScanPage", "SettingsPage", "AUTO_QUARANTINE_CHOICES",
           "detect_autostart"]
