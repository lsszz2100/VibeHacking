const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

async function capture() {
  const outDir = path.join(__dirname, '..', 'assets', 'promo');
  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  console.log('[*] Launching browser to capture Product Hunt media assets...');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    deviceScaleFactor: 2, // High-DPI retina screenshots
  });
  const page = await context.newPage();

  // 1. Wargame Live Terminal
  console.log('[*] Navigating to VibeHacking Wargame...');
  await page.goto('https://lsszz2100.github.io/VibeHacking/wargame/', { waitUntil: 'networkidle', timeout: 30000 });
  await page.waitForTimeout(2000);
  const wargamePath = path.join(outDir, 'producthunt_gallery_1_wargame.png');
  await page.screenshot({ path: wargamePath });
  console.log(`[+] Captured Wargame screenshot: ${wargamePath}`);

  // 2. Main Portal / Docsify
  console.log('[*] Navigating to VibeHacking Main Portal...');
  await page.goto('https://lsszz2100.github.io/VibeHacking/', { waitUntil: 'networkidle', timeout: 30000 });
  await page.waitForTimeout(2000);
  const portalPath = path.join(outDir, 'producthunt_gallery_2_portal.png');
  await page.screenshot({ path: portalPath });
  console.log(`[+] Captured Main Portal screenshot: ${portalPath}`);

  // 3. Square Thumbnail from Terminal Center
  const thumbPath = path.join(outDir, 'producthunt_thumbnail_square.png');
  await page.goto('https://lsszz2100.github.io/VibeHacking/wargame/', { waitUntil: 'networkidle', timeout: 30000 });
  await page.setViewportSize({ width: 800, height: 800 });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: thumbPath });
  console.log(`[+] Captured Square Thumbnail: ${thumbPath}`);

  await browser.close();
  console.log('[+] All Product Hunt media assets generated successfully!');
}

capture().catch((err) => {
  console.error('[-] Error capturing assets:', err);
  process.exit(1);
});
