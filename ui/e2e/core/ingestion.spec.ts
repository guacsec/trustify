import { gzipSync } from 'node:zlib';
import { test, expect, freshSbom, hostDocument, trackUpload, apiURL } from '../support';

test('file upload is visible in the SBOM list and a second upload is a duplicate', async ({ page, owned }) => {
  const data = await freshSbom();
  await page.goto('/ingest');
  await page.locator('input[type=file]').setInputFiles({ name: 'document.json', mimeType: 'application/json', buffer: data });
  await trackUpload(page, owned, () => page.getByRole('button', { name: 'Upload', exact: true }).click());
  await expect(page.getByText('Document ingested: document.json')).toBeVisible();
  await page.locator('input[type=file]').setInputFiles({ name: 'document.json', mimeType: 'application/json', buffer: data });
  await page.getByRole('button', { name: 'Upload', exact: true }).click();
  await expect(page.getByText('Document already exists: document.json')).toBeVisible();
  await page.goto('/');
  await page.getByPlaceholder('Search SBOMs...').fill(JSON.parse(data.toString()).metadata.component.name);
  await page.getByPlaceholder('Search SBOMs...').press('Tab');
  await expect(page.getByRole('row').filter({ hasText: JSON.parse(data.toString()).metadata.component.name })).toBeVisible();
});

test('multiple files and compressed input are independently ingested', async ({ page, owned }) => {
  await page.goto('/ingest');
  await page.locator('input[type=file]').setInputFiles([
    { name: 'first.json', mimeType: 'application/json', buffer: await freshSbom() },
    { name: 'second.json.gz', mimeType: 'application/gzip', buffer: gzipSync(await freshSbom()) },
  ]);
  const ids: string[] = [];
  page.on('response', async response => {
    if (response.url().endsWith('/api/v3/upload') && response.ok()) ids.push((await response.json()).id);
  });
  await page.getByRole('button', { name: 'Upload', exact: true }).click();
  try {
    await expect(page.getByText('Document ingested: first.json')).toBeVisible();
    await expect(page.getByText('Document ingested: second.json.gz')).toBeVisible();
    expect(ids).toHaveLength(2);
  } finally { owned.sboms.push(...ids); }
});

test('failed files remain selected and can be retried', async ({ page, owned, allowedApiErrors }) => {
  allowedApiErrors.push('/api/v3/upload');
  await page.goto('/ingest');
  await page.locator('input[type=file]').setInputFiles({ name: 'retry.json', mimeType: 'application/json', buffer: await freshSbom() });
  await page.route('**/api/v3/upload', route => route.fulfill({ status: 503, body: 'Temporary ingestion failure' }), { times: 1 });
  await page.getByRole('button', { name: 'Upload', exact: true }).click();
  await expect(page.getByText('Ingestion failed: retry.json')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Upload', exact: true })).toBeEnabled();
  await trackUpload(page, owned, () => page.getByRole('button', { name: 'Upload', exact: true }).click());
  await expect(page.getByText('Document ingested: retry.json')).toBeVisible();
});

test('malformed documents display the backend error', async ({ page, allowedApiErrors }) => {
  allowedApiErrors.push('/api/v3/upload');
  await page.goto('/ingest');
  await page.locator('input[type=file]').setInputFiles({ name: 'invalid.json', mimeType: 'application/json', buffer: Buffer.from('{invalid') });
  await page.getByRole('button', { name: 'Upload', exact: true }).click();
  await expect(page.getByText('Ingestion failed: invalid.json')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Upload', exact: true })).toBeEnabled();
});

test('URL ingestion downloads from the local fixture server', async ({ page, owned }) => {
  const url = await hostDocument(await freshSbom(), owned);
  await page.goto('/ingest');
  await page.getByRole('button', { name: 'From URL', exact: true }).click();
  await page.getByPlaceholder('https://example.com/document.json').fill(url);
  await trackUpload(page, owned, () => page.getByRole('button', { name: 'Ingest', exact: true }).click());
  await expect(page.getByText(`Document ingested: ${url}`)).toBeVisible();
});

test('drag and drop ingests a file through the sidebar', async ({ page, owned }) => {
  await page.goto('/');
  const data = await freshSbom();
  const transfer = await page.evaluateHandle(text => {
    const transfer = new DataTransfer();
    transfer.items.add(new File([text], 'dropped.json', { type: 'application/json' }));
    return transfer;
  }, data.toString());
  // The sidebar exposes a dedicated labelled drop zone.
  await trackUpload(page, owned, async () => {
    const zone = page.getByRole('region', { name: 'Ingest documents' });
    await zone.dispatchEvent('dragover', { dataTransfer: transfer });
    await zone.dispatchEvent('drop', { dataTransfer: transfer });
  });
  await expect(page.getByText(/Document ingested.*dropped.json/)).toBeVisible();
  await transfer.dispose();
});
