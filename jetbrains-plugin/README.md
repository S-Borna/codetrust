# CodeTrust JetBrains Plugin

AI Governance Enforcement Platform for IntelliJ IDEA, PyCharm, WebStorm, and all JetBrains IDEs.

## Features

- **Real-time scanning** on file save with inline annotations
- **1,200+ rules** covering security, anti-patterns, and enterprise standards across 23 languages
- **Tool window** with findings tree, severity filtering, and click-to-navigate
- **Deep scan** with AST analysis and registry verification
- **Configurable** API endpoint, severity thresholds, and language filters

## Installation

### From JetBrains Marketplace
1. Open Settings > Plugins > Marketplace
2. Search for "CodeTrust"
3. Install and restart

### Manual Installation
1. Download the latest `.zip` from [Releases](https://github.com/S-Borna/codetrust/releases)
2. Open Settings > Plugins > Install Plugin from Disk
3. Select the downloaded file and restart

## Configuration

1. Open Settings > Tools > CodeTrust
2. Enter your API endpoint (default: `https://api.codetrust.ai`)
3. Enter your API key
4. Configure scan-on-save, minimum severity, and enabled languages

## Usage

- **Automatic:** Files are scanned on save (configurable)
- **Manual:** Tools > CodeTrust > Scan Current File / Scan Project
- **Context menu:** Right-click in editor > CodeTrust: Scan File
- **Tool window:** View > Tool Windows > CodeTrust

## Building from Source

```bash
./gradlew buildPlugin
```

The plugin ZIP will be in `build/distributions/`.

## Requirements

- IntelliJ IDEA 2024.1+ (or any JetBrains IDE based on it)
- CodeTrust API key (get one at https://codetrust.ai)

## License

Copyright (c) 2026 Said Borna. All rights reserved. See LICENSE.
