# Contributing to iToWindows Unlock

Thank you for your interest in contributing! Here's how to get involved.

---

## Ways to contribute

- 🐛 Report bugs via [GitHub Issues](https://github.com/dev-rockstar23/iToWindows/issues)
- 💡 Suggest features via [GitHub Discussions](https://github.com/dev-rockstar23/iToWindows/discussions)
- 🔧 Submit pull requests for bug fixes or improvements
- 📖 Improve documentation

---

## Development setup

### Windows components

```bash
git clone https://github.com/dev-rockstar23/iToWindows.git
cd iToWindows
dotnet restore
dotnet build
dotnet test
```

Requires: Windows 11, .NET 8 SDK, Visual Studio 2022 or VS Code with C# Dev Kit.

### iOS app

Requires: Mac, Xcode 15+. See [PCUnlockApp/SETUP.md](PCUnlockApp/SETUP.md).

---

## Pull request guidelines

1. **Fork** the repo and create a branch from `main`:
   ```bash
   git checkout -b fix/your-fix-name
   ```

2. **Make your changes.** Keep commits focused — one logical change per commit.

3. **Run tests** before submitting:
   ```bash
   dotnet test
   ```

4. **Write a clear PR description** explaining what changed and why.

5. **Open the PR** against the `main` branch.

---

## Code style

- **C#:** Follow the existing file style. Use `var` where the type is obvious. XML doc comments on all public APIs.
- **Swift:** Follow Swift API Design Guidelines. Use `// MARK:` sections to organise files.
- **No custom crypto** — only platform APIs (CNG on Windows, CryptoKit on iOS).
- **Security-sensitive changes** (auth flow, BLE framing, crypto) require extra review — expect back-and-forth.

---

## Reporting security vulnerabilities

**Do not open a public issue for security vulnerabilities.**

Please report them privately via [GitHub Security Advisories](https://github.com/dev-rockstar23/iToWindows/security/advisories/new).

---

## Code of Conduct

Be respectful and constructive. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
