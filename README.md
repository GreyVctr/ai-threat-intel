# AI Shield Intelligence

A specialized threat intelligence system for AI/ML security, providing proactive defense against emerging AI-specific attacks through automated monitoring, analysis, and alerting.

## Overview

AI Shield Intelligence systematically identifies, analyzes, and distributes intelligence about emerging threats to AI systems before they impact production services. The system monitors academic papers, security research, GitHub repositories, CVE databases, and community discussions from configurable sources including arXiv, security blogs, Reddit, Hacker News, and more.

## Documentation

### Product Documentation

- **[One-Pager](ai-shield-intelligence-one-pager.md)** - Executive summary of the product vision, value proposition, and go-to-market strategy
- **[Technical Architecture](ai-shield-technical-architecture.md)** - System architecture overview, component details, and technology stack
- **[PR/FAQ](ai-threat-intel-prfaq.md)** - Press release and frequently asked questions about the service

### Deployment Profiles

AI Shield Intelligence supports multiple deployment profiles to meet different organizational needs:

#### 1. Minimal Local Profile

**Status**: Fully functional and ready to deploy

A minimal local deployment system designed for early pilots and smaller teams. Optimized for Apple Silicon Macs (M3 Max or newer) with 32 GB RAM, and 50-100 GB disk space.

**Dashboard Preview**:
![AI Shield Intelligence Dashboard](images/minimal-local-dashboard.png)
*Real-time threat intelligence dashboard showing threat distribution, recent threats, and system health monitoring*

**Threat Details View**:
![Threat Details - Attacking Machine Learning with Adversarial Examples](images/threat-details.png)
*Detailed threat view showing classification, metadata, MITRE ATLAS mappings, and LLM-generated analysis*

**Features**:
- 8 containerized services (PostgreSQL, Redis, MinIO, Ollama, FastAPI, Celery, React)
- Automated threat collection from 17 configurable sources (expandable)
- NLP classification and entity extraction
- MITRE ATLAS mapping and severity scoring
- Local LLM analysis (Ollama with Qwen2.5:7b)
- Full-text search with fuzzy matching
- Alert notifications (email, webhook)

**Default Sources** (17 configured, fully customizable):
- Academic: arXiv (Computer Security, ML, AI, Statistics)
- Security Research: Google Project Zero, Trail of Bits, NCC Group, Schneier on Security
- Vulnerability Databases: NVD CVEs, CERT/CC
- Code Repositories: GitHub Trending (Security + ML, AI Security)
- AI Research: OpenAI Blog, DeepMind Blog
- Community: Reddit (r/MachineLearning, r/netsec), Hacker News

**Documentation**: [src/minimal-local/README.md](src/minimal-local/README.md)



**Quick Start**:
```bash
cd src/minimal-local
cp .env.example .env.minimal
# Edit .env.minimal with your passwords
docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d
```

#### 2. AWS Deployment Profile

**Status**: Work in Progress - Design phase, implementation planned

A scalable, production-grade AWS deployment using managed services for enterprise workloads. Designed to support 50+ academic sources and 30+ industry sources with high-volume processing.

**Planned Features**:
- Multi-AZ high availability
- Auto-scaling based on workload
- Managed services (RDS, ElastiCache, S3, Bedrock)
- CloudWatch monitoring and alerting
- VPC isolation and security groups
- Infrastructure as Code (Terraform/CDK)
- Expanded source coverage (50+ academic, 30+ industry)

**Design Document**: [src/aws-deployment/aws-design_concept.md](src/aws-deployment/aws-design_concept.md)

**Status**: Architecture design complete, implementation not yet started. Contributions welcome!

## Key Capabilities

### Threat Collection
- Automated monitoring of academic papers (arXiv, conferences)
- GitHub repository and PoC tracking
- Security blog and advisory aggregation
- RSS/API-based collection with hot-reload configuration

### Analysis & Enrichment
- NLP-based threat classification (adversarial, poisoning, extraction, etc.)
- Entity extraction (CVEs, frameworks, techniques, models)
- MITRE ATLAS tactic and technique mapping
- Severity scoring (1-10 scale)
- Optional LLM analysis for summaries and mitigations

### Distribution
- Real-time alerts for high-severity threats
- Weekly threat intelligence briefings
- REST API for programmatic access
- SIEM/SOAR integration support
- Customizable alert thresholds and filters

## Threat Coverage

AI Shield Intelligence covers all categories of AI security threats:

- **Adversarial Attacks**: Evasion, poisoning, backdoors
- **Model Extraction**: Model stealing and parameter theft
- **Privacy Attacks**: Membership inference, model inversion
- **Prompt Attacks**: Injection, jailbreaking for LLMs
- **Data Poisoning**: Training data manipulation
- **Supply Chain**: Attacks on AI components and dependencies

## Technology Stack

| Component | Technologies |
|-----------|-------------|
| Backend | Python, FastAPI, SQLAlchemy, Celery |
| Database | PostgreSQL with full-text search (pg_trgm) |
| Cache/Queue | Redis |
| Object Storage | MinIO (local) / S3 (AWS) |
| LLM Runtime | Ollama (local) / Bedrock (AWS) |
| Frontend | React, TypeScript, Vite, Tailwind CSS |
| Collectors | RSS (feedparser), HTTP (httpx), Web scraping (BeautifulSoup4) |
| Orchestration | Docker Compose (local) / ECS (AWS) |
| Infrastructure | Terraform/CDK (AWS planned) |

## Getting Started

Choose your deployment profile and follow the respective guide:

### Minimal Local Deployment (Ready Now)

For early pilots, development, or smaller teams:

```bash
cd src/minimal-local
# Follow the detailed guide in src/minimal-local/README.md
```

**Full Instructions**: [src/minimal-local/README.md](src/minimal-local/README.md)

**Quick Summary**:
1. Copy `.env.example` to `.env.minimal` and set passwords
2. Run `docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d`
3. Initialize database and create admin user
4. Pull LLM model: `ollama pull qwen2.5:7b`
5. Access API at http://localhost:8000

### AWS Deployment (Planned)

For production, enterprise workloads:

**Design Document**: [src/aws-deployment/aws-design_concept.md](src/aws-deployment/aws-design_concept.md)

**Status**: Architecture design complete, implementation not yet started.

## Project Structure

```
.
├── README.md                                    # This file
├── ai-shield-intelligence-one-pager.md          # Product overview
├── ai-shield-technical-architecture.md          # System architecture
├── ai-threat-intel-prfaq.md                     # PR/FAQ document
└── src/
    ├── minimal-local/                           # Minimal local deployment (Available)
    │   ├── README.md                            # Deployment guide
    │   ├── docker-compose.minimal.yml           # Service definitions
    │   ├── backend/                             # Python FastAPI backend
    │   ├── frontend/                            # React frontend
    │   └── config/                              # Source configurations
    └── aws-deployment/                          # AWS deployment (Work in Progress)
        └── aws-design.md                        # Architecture design
```

## Development

For local development setup, testing, and contribution guidelines, see:
- **Minimal Local**: [src/minimal-local/README.md#development](src/minimal-local/README.md#development)
- **Contributing**: Areas where we'd especially appreciate help:
  - AWS deployment implementation
  - Additional threat source collectors
  - Enhanced NLP classification models
  - SIEM/SOAR integrations
  - Frontend improvements
  - Documentation and examples

## Roadmap

### Completed
- [x] Minimal local deployment profile
- [x] Automated threat collection (RSS, API, web scraping)
- [x] NLP classification and entity extraction
- [x] MITRE ATLAS mapping
- [x] Local LLM analysis with Ollama
- [x] Full-text search with PostgreSQL
- [x] Alert notifications (email, webhook)
- [x] REST API with authentication
- [x] React frontend (basic)

### In Progress
- [ ] AWS deployment profile
- [ ] Enhanced frontend features
- [ ] Additional SIEM integrations

### Planned
- [ ] Multi-language support
- [ ] Advanced threat correlation
- [ ] Threat intelligence platform (TIP) integrations
- [ ] Custom ML model training
- [ ] Threat hunting workflows
- [ ] Mobile app for alerts

## Support

For detailed troubleshooting, configuration, and usage instructions, see the deployment-specific README:

- **Minimal Local**: [src/minimal-local/README.md](src/minimal-local/README.md)
- **AWS Deployment**: [src/aws-deployment/aws-design_concept.md](src/aws-deployment/aws-design_concept.md)

Quick health check:
```bash
curl http://localhost:8000/api/v1/health
```

## License

See LICENSE file in the project root.

---

*"Traditional threat intelligence wasn't built for AI. We're changing that."*
