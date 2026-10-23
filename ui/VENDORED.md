# Third-party files of the web interface

All files below are embedded into the `whawty-auth` binary so that the web
interface works without internet access. Only add files whose license allows
redistribution in binary form, put the license text next to them and record
them here. The SHA-256 sums are those of the files in this directory and can
be compared with the published package to verify a file.

| File(s) in `assets/` | Project | Version | License | Source |
|---|---|---|---|---|
| `vendor/zxcvbn/zxcvbn.js` | [zxcvbn](https://github.com/dropbox/zxcvbn) | 4.4.2 | MIT, see `vendor/zxcvbn/LICENSE.txt` | npm package `zxcvbn@4.4.2`, `dist/zxcvbn.js` |

SHA-256:

```
f42c651f40506acb6b662490f338dd47a5951d3312039c4ab8fe5090484f351a  vendor/zxcvbn/zxcvbn.js
```

## To be removed with the old web interface

These files are only used by the Bootstrap based web interface. Their license
notices are part of the file headers.

| File(s) in `assets/` | Project | Version | License | Source |
|---|---|---|---|---|
| `bootstrap/css/bootstrap.min.css`, `bootstrap/js/bootstrap.bundle.min.js` | [Bootstrap](https://getbootstrap.com/) | 5.0.2 | MIT | npm package `bootstrap@5.0.2`, `dist/` |
| `jquery/jquery.min.js` | [jQuery](https://jquery.com/) | 3.7.0 | MIT | npm package `jquery@3.7.0`, `dist/` |
| `fontawesome/css/*.min.css`, `fontawesome/webfonts/fa-solid-900.*` | [Font Awesome Free](https://fontawesome.com/) | 6.4.0 | Icons: CC BY 4.0, fonts: SIL OFL 1.1, code: MIT | npm package `@fortawesome/fontawesome-free@6.4.0` |

SHA-256:

```
7633b7c0c97d19e682feee8afa2738523fcb2a14544a550572caeecd2eefe66b  bootstrap/css/bootstrap.min.css
7e1f1503df765cca5e099891b94e318a2ef95081ba2af1eb6d417cc884bfdbfe  bootstrap/js/bootstrap.bundle.min.js
d8f9afbf492e4c139e9d2bcb9ba6ef7c14921eb509fb703bc7a3f911b774eff8  jquery/jquery.min.js
3dc869c82a722d9fd7c7d881a453ee3d269d461917c7a27901ad357d9dcbbfc4  fontawesome/css/fontawesome.min.css
b43dcc895ec8fa778047b69062f1920729246b946fba0c34cddd15e558a801e3  fontawesome/css/solid.min.css
67a65763c7f80903d81603bbeb9049fc2bf28508479b83ed011fe24c71fa950a  fontawesome/webfonts/fa-solid-900.ttf
7152a6933ee3d690ec2af3d09da9d701723d16aa3410a6d80f28ff8866f3b880  fontawesome/webfonts/fa-solid-900.woff2
```
