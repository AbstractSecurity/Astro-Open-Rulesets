# Astro-Open-Rulesets

This repository contains open-source rulesets developed and maintained by the Abstract Security Threat Research Organization (ASTRO). These rules are designed to aid in threat detection and DFIR activities.

## Project Overview

Astro-Open-Rulesets provides detection capabilities for various threat types. These rules can be integrated into your security tools and workflows to enhance detection capabilities.

## Repository Structure

```
├── LICENSE              # License information
├── README.md            # This file
└── yara-rules/          # Main directory for all YARA rules
    ├── dfir/            # Digital Forensics & Incident Response rules
    └── macos/           # macOS specific detection rules

```

## Rule Categories

### DFIR (Digital Forensics & Incident Response)

Rules in this category focus on identifying sensitive information and artifacts useful during incident response.

### macOS

Rules specific to macOS threat detection


## Usage

These YARA rules can be used with any tool that supports the YARA format, including:

- YARA CLI
- ClamAV (with YARA support)
- Various EDR and security products
- Forensic analysis frameworks

## Contributing

Contributions are welcome! If you have improvements to existing rules or new rules to add, please submit a pull request.

## License

See the [LICENSE](LICENSE) file for details.

## About ASTRO

Abstract Security Threat Research Organization (ASTRO) is dedicated to researching and sharing information about emerging threats.
