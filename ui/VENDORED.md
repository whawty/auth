# Third-party files of the web interface

All files below are embedded into the `whawty-auth` binary so that the web
interface works without internet access. Only add files whose license allows
redistribution in binary form, put the license text next to them and record
them here. The SHA-256 sums are those of the files in this directory and can
be compared with the published package to verify a file.

The icon sprite only contains the icons listed in `UI_ICONS` in the Makefile.
To add an icon or update Lucide, change `UI_ICONS` or `LUCIDE_VERSION` and
`LUCIDE_SHA256` there and run `make ui-icons`.

| File(s) in `assets/` | Project | Version | License | Source |
|---|---|---|---|---|
| `vendor/lucide/icons.svg` | [Lucide](https://lucide.dev/) | 1.59.0 | ISC, some icons MIT, see `vendor/lucide/LICENSE` | generated from the npm package `lucide-static@1.59.0` with `make ui-icons` |
| `img/favicon.svg` | [Lucide](https://lucide.dev/) | 1.59.0 | ISC, see `vendor/lucide/LICENSE` | the `lock-keyhole` icon, black or white depending on the browser theme, made by hand |
| `vendor/zxcvbn/zxcvbn.js` | [zxcvbn](https://github.com/dropbox/zxcvbn) | 4.4.2 | MIT, see `vendor/zxcvbn/LICENSE.txt` | npm package `zxcvbn@4.4.2`, `dist/zxcvbn.js` |

SHA-256:

```
6ef51a87657461ce958b992ac5539638ec0710a58ed4087dad19e232b6c2b216  vendor/lucide/icons.svg
f42c651f40506acb6b662490f338dd47a5951d3312039c4ab8fe5090484f351a  vendor/zxcvbn/zxcvbn.js
```

