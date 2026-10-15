#!/usr/bin/env python3
"""
detectors/__init__.py — Unified exports for all AEGIS SENTINEL v5.2.0 detectors.
"""

from .fuzzy_hash import FUZZY_AVAILABLE, FuzzyHasher, FuzzyMatch, FuzzyResult
from .macro_analysis import OLEVBA_AVAILABLE, MacroAnalyzer, MacroResult
from .yara_engine import YARA_AVAILABLE, YaraEngine, YaraMatch, YaraResult
from .prompt_guard import HiddenTextResult, PromptGuard, PromptGuardResult, wrap_untrusted_with_nonce
from .llm_backends import LLMBackend, NullLLMBackend, OllamaBackend, OpenAIBackend, build_llm_backend
from .container_extractor import ContainerExtractionResult, ContainerExtractor
from .relationship_scanner import RelationshipFinding, RelationshipScanResult, RelationshipScanner
from .mail_analyzer import AuthMechanismResult, MailAnalysisResult, MailAnalyzer
from .behavioral_monitor import BehavioralFinding, BehavioralMonitor, BehavioralReport, calculate_shannon_entropy
from .multi_format_analyzer import MultiFormatAnalyzer, MultiFormatResult
from .dynamic_sandbox import DynamicSandbox, SandboxReport
from .memory_scanner import MemoryFinding, MemoryForensicsScanner, MemoryScanSummary, ProcessMemoryReport
from .ml_classifier import FILE_FEATURE_NAMES, MLMalwareClassifier, MLPrediction
from .llm_analyst import AnalystBriefing, LocalLLMThreatAnalyst
from .ai_correlator import AIDetectionCorrelator, CorrelatedDecision
from .scoring import Contribution, ScoreResult, ScoringMatrix

__all__ = [
    "FUZZY_AVAILABLE",
    "FuzzyHasher",
    "FuzzyMatch",
    "FuzzyResult",
    "OLEVBA_AVAILABLE",
    "MacroAnalyzer",
    "MacroResult",
    "YARA_AVAILABLE",
    "YaraEngine",
    "YaraMatch",
    "YaraResult",
    "HiddenTextResult",
    "PromptGuard",
    "PromptGuardResult",
    "wrap_untrusted_with_nonce",
    "LLMBackend",
    "NullLLMBackend",
    "OllamaBackend",
    "OpenAIBackend",
    "build_llm_backend",
    "ContainerExtractionResult",
    "ContainerExtractor",
    "RelationshipFinding",
    "RelationshipScanResult",
    "RelationshipScanner",
    "AuthMechanismResult",
    "MailAnalysisResult",
    "MailAnalyzer",
    "BehavioralFinding",
    "BehavioralMonitor",
    "BehavioralReport",
    "calculate_shannon_entropy",
    "MultiFormatAnalyzer",
    "MultiFormatResult",
    "DynamicSandbox",
    "SandboxReport",
    "MemoryFinding",
    "MemoryForensicsScanner",
    "MemoryScanSummary",
    "ProcessMemoryReport",
    "FILE_FEATURE_NAMES",
    "MLMalwareClassifier",
    "MLPrediction",
    "AnalystBriefing",
    "LocalLLMThreatAnalyst",
    "AIDetectionCorrelator",
    "CorrelatedDecision",
    "Contribution",
    "ScoreResult",
    "ScoringMatrix",
]