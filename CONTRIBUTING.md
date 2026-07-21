# Contributing to Creduent JS/TS SDK

Thank you for your interest in contributing to the Creduent JS/TS SDK! This guide helps you set up your local development environment and details our contribution guidelines.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating. By contributing, you agree to abide by its terms.

---

## Contributor Licensing (DCO)

By submitting a Pull Request, you certify that your contribution is made under the terms of the [Developer Certificate of Origin](https://developercertificate.org). Add a sign-off to every commit:

```bash
git commit -s -m "your commit message"
```

This adds a `Signed-off-by: Your Name <your@email.com>` line to your commit. Pull Requests without a sign-off on every commit will not be merged.

---

## Development Setup

1. **Clone the Repository:**

    ```bash
    git clone https://github.com/idevsec/creduent-js.git
    cd creduent-js
    ```

2. **Install Dependencies:**

    ```bash
    npm install
    ```

3. **Build the SDK:**
   Compiles ESM/CommonJS targets and generates TypeScript declaration files:

    ```bash
    npm run build
    ```

4. **Run the Test Suite:**
   Verify your setup by running the unit tests:
    ```bash
    npm run test
    ```

---

## Code Guidelines & Robustness Guarantees

Please ensure all contributions respect the SDK's lightweight and zero-dependency philosophy:

- **Zero Runtime Dependencies:** Do not add third-party NPM packages for runtime cryptographic operations or JCS formatting. Rely strictly on the standard built-in `globalThis.crypto.subtle` (Web Crypto API).
- **Cross-Runtime Compatibility:** Ensure codebase changes run cleanly in Node.js 18+, Edge environments (Vercel Edge, Cloudflare Workers), Deno, and modern web browsers.
- **Canonicalization:** Ensure all payloads conform to RFC 8785 JSON Canonicalization Scheme (JCS) before signing or verifying.

---

## Git Workflow & Branching Strategy

To keep the repository clean and manageable, please follow our branching conventions:

### Branch Naming Conventions

- **Features:** Use prefix `feature/` (e.g., `feature/vercel-ai-sdk-upgrade`) for new API methods or framework integrations.
- **Bugfixes:** Use prefix `bugfix/` (e.g., `bugfix/edge-crypto-subtle-fix`) for fixing bugs or issues.
- **Documentation:** Use prefix `docs/` (e.g., `docs/quickstart-guide-update`) for changes to documentation or README files.
- **Refactoring:** Use prefix `refactor/` (e.g., `refactor/modular-verifiers`) for code refactors with no functional changes.

### Pull Request Process

1. Create a local branch from the `main` branch following the naming conventions above.
2. Make changes and verify them locally. Ensure code formatting is clean.
3. Push your branch to GitHub.
4. Open a Pull Request (PR) against the `main` branch.
5. Fill out the Pull Request template completely.
6. Ensure any checks (CI workflows) pass and request review from maintainers.

---

## Commit Message Conventions

We follow the Conventional Commits specification. Commit messages must be structured as follows:

```text
<type>(<scope>): <description>

[optional body]
```

Allowed types include:
- `feat`: A new protocol feature or SDK capability.
- `fix`: A bug fix in the reference implementation or schema.
- `docs`: Documentation updates.
- `refactor`: Code changes that do not alter behavior.

---

## Project Roadmap & Wanted Features

The Creduent JS/TS SDK follows the global [Creduent Protocol Roadmap](https://github.com/idevsec/creduent/blob/main/ROADMAP.md). If you are looking for specific ways to contribute to the JS/TS ecosystem, please refer to our active hotspots below:

### JS/TS SDK Active Hotspots
* **Framework Integrations (Phase 4):** Implement native verification helper middlewares or tool-wrappers for:
  * **LangChain JS** (similar to our Python integration adapters).
  * **LlamaIndex TS** (zero-dependency integration classes).
* **Local Cache Tuning (Phase 4):** Build a configurable, in-memory LRU cache wrapper for verification checks (with a 5-minute default TTL) inside `src/verifier.ts` to reduce duplicate registry API fetches.
* **Delegation (CREDUENT-007 / Phase 5):** Assist in building the recursive chain validator `verifyDelegationChain()` to verify parent-child authorization tokens locally.

Before opening a Pull Request for a new feature, please open an Issue to align on the specification and design.

