# Verified Trust Badges & Seals

`lory badge` generates official **Secured by Lorikeet Security** trust badges, seals, and shields for websites, SaaS footers, documentation, and open-source repositories.

---

## 1. Generating a Badge (`lory badge`)

Generate badges directly from the command line:

```bash
# Generate the default dark pill badge for a domain
lory badge acme.com

# Generate a continuous verification seal
lory badge acme.com --style=seal --theme=dark

# Generate a dual-tone shield badge
lory badge acme.com --style=shield --theme=dark

# Export badge directly to an SVG file
lory badge acme.com --style=pill --theme=dark --format=svg --out=lorikeet-badge.svg
```

---

## 2. Available Styles & Themes

`lory` supports four distinct badge styles across dark and light themes:

| Style (`--style`) | Dimensions | Ideal For |
| :--- | :---: | :--- |
| **`pill`** (Default) | `240 × 44` px | Modern SaaS footers, pricing pages, and checkout flows |
| **`shield`** | `296 × 28` px | GitHub README headers and documentation sidebars |
| **`seal`** | `360 × 72` px | Enterprise security & compliance pages, SOC 2 trust portals |
| **`minimal`** | `180 × 36` px | Compact footers and mobile web applications |

### Themes (`--theme`)
- **`dark`**: Deep Navy background (`#0A1628` to `#142B49`), crimson accent (`#BA5663`), and emerald verification glow.
- **`light`**: Crisp white and slate container (`#FFFFFF` on `#F8FAFC`) with subtle navy and rose typography.

---

## 3. Brand Elements & Dual-Tone Shield

Every official Lorikeet Security badge features:
1. **The Talon Claw Dual-Tone Shield**: Left plate in Deep Navy (`#0A1628`), right plate in Verified Emerald (`#059669`) or Crimson Accent (`#BA5663`).
2. **Typography**: Engineered with system fonts (`Inter, -apple-system, sans-serif`) with precise tracking and zero label clipping.
3. **Verified Indicator**: Emerald dot or shield with a checkmark signifying an active passing scan on the Lorikeet Security platform.

---

## 4. Embedding Badges in Websites & READMEs

### Option A: HTML Footer Embed
```html
<a href="https://lorikeetsecurity.com/verify?domain=acme.com" target="_blank" rel="noopener noreferrer">
  <img src="https://lorikeetsecurity.com/assets/badges/lorikeet-secured-dark.svg"
       alt="Secured by Lorikeet Security"
       width="240"
       height="44" />
</a>
```

### Option B: Markdown (GitHub README)
```markdown
[![Secured by Lorikeet Security](https://lorikeetsecurity.com/assets/badges/lorikeet-secured-shield.svg)](https://lorikeetsecurity.com/verify?domain=acme.com)
```

### Option C: Inline SVG
Generating with `--format=svg` outputs zero-dependency raw vector XML that can be inlined directly into React, Vue, Svelte, or plain HTML without external network requests:

```bash
lory badge acme.com --style=shield --format=svg > public/badge.svg
```

---

## 5. Command Options & Flags

| Flag | Description | Options / Default |
| :--- | :--- | :--- |
| `--style` | Visual format of the badge | `pill`, `shield`, `seal`, `minimal` (default: `pill`) |
| `--theme` | Background palette | `dark`, `light` (default: `dark`) |
| `--format` | Output template | `all`, `html`, `markdown`, `svg` (default: `all`) |
| `--score` | Numerical assessment score | Integer `0` to `100` (default: `100`) |
| `--status` | Status label | `VERIFIED`, `PASSED`, `AUDITED` (default: `VERIFIED`) |
| `--target` | Target domain or repo | e.g. `example.com` |
| `--out` | Output destination file path | e.g. `--out=assets/badge.svg` |
| `--verify-url` | Custom verification URL | Overrides default verification link |
