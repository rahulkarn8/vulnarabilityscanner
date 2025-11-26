# DAIFEND Logo Setup Instructions

## Where to Place Your Logo

Place your DAIFEND AI CYBERSECURITY logo image file in this directory:
```
frontend/public/assets/daifend-logo.png
```

## Supported File Formats

- **PNG** (recommended): `daifend-logo.png`
- **SVG** (scalable): `daifend-logo.svg`
- **JPG**: `daifend-logo.jpg`

## Logo Specifications

Based on your logo design:
- **Recommended size**: 200-300px width
- **Height**: Will scale automatically to maintain aspect ratio
- **Display height**: 60px (will auto-scale)
- **Background**: Transparent (PNG) or white background

## Your Logo Description

Your logo features:
- A three-dimensional globe made of pixelated/square tiles
- Blue-grey tiles on left and bottom portions
- Vibrant lime green tiles on right side (breaking away/dissolving effect)
- "DAIFEND" text in medium blue (right side of logo)
- "AI CYBERSECURITY" tagline in muted grey (below DAIFEND)

## If Using Different Filename

If your logo file has a different name (e.g., `logo.svg`, `daifend.png`):

1. Update `frontend/src/components/Header.tsx` on line 163
2. Change: `src="/assets/daifend-logo.png"`
3. To match your filename: `src="/assets/your-filename.png"`

## After Adding the Logo

1. Save your logo file to: `frontend/public/assets/daifend-logo.png`
2. Refresh your browser (or the dev server will auto-reload)
3. The logo will appear in the header automatically

## Current Status

The header is already configured to display:
- Logo image (when file is added)
- "DAIFEND" text in brand blue
- "AI CYBERSECURITY" tagline in grey
- Proper spacing and alignment

The logo will display automatically once you add the image file!

