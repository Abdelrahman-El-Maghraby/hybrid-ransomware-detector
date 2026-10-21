"""
detectors - modular detection engines for the Hybrid Ransomware Detection System.

Each engine is independent, optional, and degrades gracefully when its
third-party dependency is not installed:

    fuzzy_hash            TLSH + ssdeep structural/similarity hashing
                          (polymorphic family detection)
    macro_analysis        olevba VBA/XLM macro triage, VBA-stomping detection
    yara_engine           YARA pattern matching against a rules directory
    llm_backends          pluggable LLM (local Ollama / cloud OpenAI / none)
                          with nonce-spotlighted prompts
    file_integrity        format/magic validation, disguised executables,
                          encrypted-content (ransomware impact) detection
    prompt_guard          hidden-content + prompt-injection detection
    relationship_scanner  Office external relationships (remote template
                          injection, Follina-style OLE, UNC/NTLM leaks)
    container_extractor   safe ZIP inspection (zip bomb / zip slip / lures)
    mail_analyzer         MailGuard: .eml/.msg SPF/DKIM/DMARC, spoofing,
                          deceptive links, attachment extraction
    ml_classifier         static byte/PE features + RandomForest (or a
                          transparent rule engine when no model is trained)
    elf_analysis          Linux ELF triage: packing, removed section table,
                          hostile-only strings (miners, reverse shells...)
    qr_scanner            QR codes in images / PDF / Office files and the
                          links they carry (quishing)
    scoring               transparent weighted scoring matrix
"""

from .fuzzy_hash import FuzzyHasher, FuzzyResult, FUZZY_AVAILABLE
from .macro_analysis import MacroAnalyzer, MacroResult, OLEVBA_AVAILABLE
from .yara_engine import YaraEngine, YaraResult, YARA_AVAILABLE
from .llm_backends import build_llm_backend, LLMBackend
from .file_integrity import FileIntegrityAnalyzer, IntegrityResult, ransom_indicator
from .prompt_guard import (PromptGuard, PromptGuardResult, DEFUSEDXML_AVAILABLE,
                           wrap_untrusted_with_nonce)
from .relationship_scanner import RelationshipScanner, RelationshipResult
from .container_extractor import ContainerExtractor, ContainerResult
from .mail_analyzer import MailAnalyzer, MailResult, MSG_AVAILABLE
from .ml_classifier import MLClassifier, MLResult, SKLEARN_AVAILABLE
from .scoring import ScoringMatrix, ScoreResult
from .elf_analysis import ElfAnalyzer, ElfResult
from .script_analysis import ScriptAnalyzer, ScriptResult
from .qr_scanner import QRScanner, QRResult, QR_AVAILABLE

__all__ = [
    "FuzzyHasher", "FuzzyResult", "FUZZY_AVAILABLE",
    "MacroAnalyzer", "MacroResult", "OLEVBA_AVAILABLE",
    "YaraEngine", "YaraResult", "YARA_AVAILABLE",
    "build_llm_backend", "LLMBackend",
    "FileIntegrityAnalyzer", "IntegrityResult", "ransom_indicator",
    "PromptGuard", "PromptGuardResult", "DEFUSEDXML_AVAILABLE",
    "wrap_untrusted_with_nonce",
    "RelationshipScanner", "RelationshipResult",
    "ContainerExtractor", "ContainerResult",
    "MailAnalyzer", "MailResult", "MSG_AVAILABLE",
    "MLClassifier", "MLResult", "SKLEARN_AVAILABLE",
    "ScoringMatrix", "ScoreResult",
    "ElfAnalyzer", "ElfResult", "ScriptAnalyzer", "ScriptResult", "QRScanner", "QRResult", "QR_AVAILABLE",
]
