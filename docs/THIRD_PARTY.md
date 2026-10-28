# Third-party components and services (for legal review)

This list is input for a legal review of commercial use. It records what each
component's own metadata states; **it draws no legal conclusion**. Items marked
*review* have a copyleft, public-domain/CC0, multi-licence or unstated licence
that a lawyer should look at for the way Aegis Sentinel is distributed (desktop
binaries built with PyInstaller, and Docker images).

Aegis Sentinel itself: MIT License (`LICENSE`). The bundled YARA rules state in
their headers that they were written from scratch for this project.

## Python packages (`requirements.lock`)

Version: as pinned in `requirements.lock`. Licence: the package's metadata
(`License-Expression`, `License` or the licence classifiers), read from an
installation of the locked set; a few packages were installed at a newer patch
version there, so re-check the exact pinned version during the review.
"In server image": installed in the `aegis-sentinel` Docker image (the desktop
builds include the GUI and ML packages as well).

| Package | Version | Licence (as stated) | In server image | Flag |
|---|---|---|---|---|
| annotated-doc | 0.0.5 | MIT | yes |  |
| annotated-types | 0.8.0 | MIT | yes |  |
| anyio | 4.15.1 | MIT | yes |  |
| backports-zstd | 1.8.0 | PSF-2.0 | yes |  |
| brotli | 1.2.1 | MIT | yes |  |
| certifi | 2026.10.19 | MPL-2.0 | yes | review |
| cffi | 2.1.1 | MIT-0 | yes |  |
| charset-normalizer | 3.5.2 | MIT | yes |  |
| click | 8.5.0 | BSD-3-Clause | yes |  |
| cloudpickle | 3.1.2 | BSD-3-Clause | no |  |
| colorclass | 2.2.2 | MIT | yes |  |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | yes |  |
| customtkinter | 6.0.0 | Creative Commons Zero v1.0 Universal | no | review |
| darkdetect | 0.8.0 | BSD-3-Clause | no |  |
| defusedxml | 0.7.1 | PSFL | yes |  |
| easygui | 0.98.3 | BSD | yes |  |
| fastapi | 0.158.0 | MIT | yes |  |
| h11 | 0.16.0 | MIT | yes |  |
| idna | 3.20 | BSD-3-Clause | yes |  |
| inflate64 | 1.0.4 | LGPL-2.1-or-later | yes | review |
| jaraco-classes | 3.4.0 | MIT License | yes |  |
| jaraco-context | 6.1.2 | MIT | yes |  |
| jaraco-functools | 4.6.0 | MIT | yes |  |
| jeepney | 0.9.0 | MIT | yes |  |
| joblib | 1.6.0 | BSD-3-Clause | no |  |
| keyring | 25.7.0 | MIT | yes |  |
| lxml | 6.1.3 | BSD-3-Clause | yes |  |
| more-itertools | 11.2.1 | MIT | yes |  |
| msoffcrypto-tool | 6.0.0 | MIT | yes |  |
| multivolumefile | 0.2.3 | LGPL-2.1+ | yes | review |
| narwhals | 2.27.1 | MIT | no |  |
| numpy | 2.5.4 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | yes | review |
| olefile | 0.47 | BSD | yes |  |
| oletools | 0.60.2 | BSD | yes |  |
| opentelemetry-api | 1.45.1 | Apache-2.0 | yes |  |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | no |  |
| pcodedmp | 1.2.6 | GPL | yes | review |
| pdf2image | 1.17.0 | MIT | no |  |
| pillow | 13.0.0 | MIT-CMU | yes |  |
| ppdeep | 20260221 | ASL 2.0 | yes |  |
| psutil | 7.2.2 | BSD-3-Clause | yes |  |
| py7zr | 1.1.4 | LGPL-2.1-or-later | yes | review |
| pybcj | 1.0.8 | LGPL-2.1-or-later | yes | review |
| pycdlib | 1.22.0 | LGPL-2.1-only | yes | review |
| pycparser | 3.11 | BSD-3-Clause | yes |  |
| pycryptodomex | 3.24.1 | BSD, Public Domain | yes | review |
| pydantic | 2.14.1 | MIT | yes |  |
| pydantic-core | 2.50.1 | MIT | yes |  |
| pyparsing | 3.3.3 | MIT | yes |  |
| pypdf | 6.21.2 | BSD-3-Clause | yes |  |
| pyppmd | 1.3.1 | LGPL-2.1-or-later | yes | review |
| pytesseract | 0.3.13 | Apache License 2.0 | no |  |
| python-docx | 1.2.0 | MIT | yes |  |
| python-dotenv | 1.2.4 | BSD-3-Clause | yes |  |
| python-multipart | 0.0.32 | Apache-2.0 | yes |  |
| python-tlsh | 4.5.0 | Apache or BSD | yes |  |
| pyyaml | 6.0.3 | MIT | yes |  |
| pyzbar | 0.1.9 | MIT | yes |  |
| pyzipper | 0.4.0 | MIT | yes |  |
| rarfile | 4.5 | ISC | yes |  |
| requests | 2.34.2 | Apache-2.0 | yes |  |
| schedule | 1.2.2 | MIT License | yes |  |
| scikit-learn | 1.9.1 | BSD-3-Clause | no |  |
| scipy | 1.18.1 | BSD License | no |  |
| secretstorage | 3.5.0 | BSD-3-Clause | yes |  |
| starlette | 1.9.0 | BSD-3-Clause | yes |  |
| texttable | 1.7.2 | MIT | yes |  |
| threadpoolctl | 3.7.0 | BSD-3-Clause | no |  |
| typing-extensions | 4.16.0 | PSF-2.0 | yes |  |
| typing-inspection | 0.4.4 | MIT | yes |  |
| urllib3 | 2.8.0 | MIT | yes |  |
| uvicorn | 0.54.0 | BSD-3-Clause | yes |  |
| watchdog | 6.0.0 | Apache-2.0 | no |  |
| yara-python | 4.5.4 | Apache 2.0 | yes |  |

## System components in the images

| Component | Where | Licence (source) | Flag |
|---|---|---|---|
| Python 3.12 (`python:3.12-slim-trixie`) | server image | PSF License (python.org) | |
| Debian 13 base packages | server image | various; the list ships with each release (`*.debian-packages.txt`) | review |
| unar 1.10.8 (Debian `unar`) | server image, RAR extraction | LGPL-2.1+ and BSD-3-Clause (Debian copyright file in the image) | review |
| ZBar 0.23.93 (Debian `libzbar0t64`) | server image, QR decoding | LGPL-2.1 per the upstream ZBar project; Debian's copyright file is not in the slim image, so confirm | review |
| Caddy 2.10.2 (`caddy:2.10.2-alpine`) | proxy image | Apache-2.0 (upstream) | |
| Alpine Linux base | proxy image | various | review |
| PyInstaller bootloader | desktop binaries | GPL-2.0 with a bootloader exception (upstream) | review |

## External services (only when the customer enables them)

The product calls these only when configured (`docs/DATA_POLICY.md`). Their terms
govern the customer's use; review whether they fit a commercial deployment and
who must hold the account.

| Service | Used for | Terms to review |
|---|---|---|
| VirusTotal API (Google) | hash look-up; file upload if enabled | VirusTotal Terms of Service and API terms, including the conditions for the public (free) API versus a premium licence, and what happens to uploaded files |
| OpenAI API | LLM analysis with `LLM_PROVIDER=openai` | OpenAI terms of use / API data-usage policies |
| Ollama and the chosen model | local LLM analysis | Ollama's licence and the licence of the model weights the customer installs (they differ per model) |
| CAPEv2 sandbox | dynamic analysis on the customer's server | CAPEv2's licence (the customer runs it; not shipped with Aegis Sentinel) |
| MalwareBazaar / sample sources | evaluation by the owner, not shipped | the terms of the sample source |

## Not shipped

Test and build tools (pytest, ruff, mypy, bandit, pip-audit, cyclonedx-bom) are
used to build and check the product and are not part of the shipped artifacts.
