// Copyright (c) Said Borna. All rights reserved.
/**
 * Pings IndexNow API to notify Bing (and other search engines) of updated URLs.
 * Run after git push: node scripts/indexnow-ping.mjs
 */

const INDEX_NOW_KEY = '4b992833761e446f97a4e6e3f7ce6ef0';
const HOST = 'codetrust.ai';
const KEY_LOCATION = `https://${HOST}/${INDEX_NOW_KEY}.txt`;

const URLS = [
  `https://${HOST}/`,
  `https://${HOST}/privacy.html`,
  `https://${HOST}/llms.txt`,
  `https://${HOST}/llms-full.txt`,
  `https://${HOST}/sitemap.xml`,
  `https://${HOST}/.well-known/ai-plugin.json`,
];

const ENDPOINT = 'https://api.indexnow.org/indexnow';

async function ping() {
  const body = JSON.stringify({
    host: HOST,
    key: INDEX_NOW_KEY,
    keyLocation: KEY_LOCATION,
    urlList: URLS,
  });

  console.log(`Pinging IndexNow for ${URLS.length} URLs...`);

  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
    body,
  });

  if (res.ok) {
    console.log(`✅ IndexNow accepted — HTTP ${res.status}`);
  } else {
    const text = await res.text();
    console.error(`❌ IndexNow rejected — HTTP ${res.status}: ${text}`);
    process.exit(1);
  }
}

ping().catch(err => { console.error(err); process.exit(1); });
