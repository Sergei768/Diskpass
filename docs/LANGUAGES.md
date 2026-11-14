# Diskpass documentation layout

Default GitHub entry point: `README.md` (English).

The 12 documentation languages match the built-in selection in `diskpass_i18n.c`:

- `en`: `README.md`
- `ru`: `docs/README.ru.md`
- `uk`: `docs/README.uk.md`
- `be`: `docs/README.be.md`
- `kk`: `docs/README.kk.md`
- `zh_CN`: `docs/README.zh_CN.md`
- `zh_TW`: `docs/README.zh_TW.md`
- `ja`: `docs/README.ja.md`
- `ko`: `docs/README.ko.md`
- `fr`: `docs/README.fr.md`
- `de`: `docs/README.de.md`
- `es`: `docs/README.es.md`

Every README uses the same three English SVG diagrams located directly under `docs/diagrams/`: `tags.svg`, `encryption.svg`, and `steganography.svg`. Diagram labels are English in all language versions; paths are relative to each README. The original SVG banner is `docs/assets/logo.svg`. All three technical diagrams and the header are SVG; the non-English diagram variants have been removed. The current logo is `docs/assets/logo.svg`. Other image assets (`screenshot.png`, `Tag_format.png`) are stored under `docs/assets/`; no image files need to remain in the repository root.

The app source and binary are not changed. Each translation is documentation text; it does not imply complete GUI translation coverage for every locale.

## Installation

Copy `README.md` and the complete `docs/` directory into the repository root. The only README in the root directory is the English version; all translations, banner and diagrams live under `docs/`.

## PNG assets

The following original project images are available under `docs/assets/`:

- `docs/assets/logo.svg`
- `docs/assets/screenshot.png`
- `docs/assets/Tag_format.png`

To reference an image from the root `README.md`, use `docs/assets/<filename>`. From any `docs/README.<locale>.md`, use `assets/<filename>`. If old PNG files are still in the repository root, remove them after confirming the copies under `docs/assets/`; extracting a ZIP does not automatically delete older tracked files.
