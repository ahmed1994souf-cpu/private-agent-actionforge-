# SvR2011 Asset Analyzer

A small, cautious forensic helper for WWE SmackDown vs. Raw 2011 mod assets. It scans EPK8/PAC-like binary files for known signatures and reports offsets; it does **not** claim to decode meshes, skeletons, or animations.

## Usage

Python 3.10+:

```bash
python tools/analyze_pac.py path/to/ch.pac --json report.json
```

The tool only reads the input and writes a text/JSON report. Keep original game files unchanged.

## GitHub Actions

Open **Actions → Analyze sample format → Run workflow** to run the built-in synthetic test. The workflow does not contain or download copyrighted game assets.

## Current known observations

A sample `hornswoggle.svrmod` archive was a ZIP containing `manifest.txt`, `ch.pac`, `moves.txt`, `render.dds`, and `render_small.dds`. The extracted `ch.pac` began with `EPK8`; observed signatures included `PACH`, `BPE `, and `DDS `. These signatures alone do not establish which chunks contain geometry or animation.

## Privacy

Do not commit ISO images, commercial game files, PAC files, mod archives, or extracted copyrighted assets to this public repository. Run the analyzer locally on a file you already possess and share only the generated report if appropriate.
