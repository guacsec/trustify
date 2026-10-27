import { test, expect, freshSbom, apiURL, uuid } from '../support';

test('OIDC authorization, authenticated upload and reads, and reload', async ({ page, request }) => {
  const discovery = await request.get(`${apiURL}/.well-known/trustify`);
  expect((await discovery.json()).frontend.oidc.issuerUrl).toBe(process.env.E2E_OIDC_URL);
  const unauthorized = await request.get(`${apiURL}/api/v3/sbom`);
  expect(unauthorized.status()).toBe(401);
  const authorization = page.waitForRequest(r => r.url().includes('/realms/trustify/') && r.url().includes('response_type=code'));
  await page.goto('/');
  expect((await authorization).url()).toContain(process.env.E2E_OIDC_URL!);
  await expect(page.getByPlaceholder('Search SBOMs...')).toBeVisible();
  const data = await freshSbom();
  let id: string | undefined;
  let token: string | undefined;
  page.on('request', request => {
    if (request.url().includes('/api/') && request.headers().authorization) token = request.headers().authorization;
  });
  try {
    await page.goto('/ingest');
    await page.locator('input[type=file]').setInputFiles({ name: 'authenticated.json', mimeType: 'application/json', buffer: data });
    const pending = page.waitForResponse(r => r.url().endsWith('/api/v3/upload'));
    await page.getByRole('button', { name: 'Upload', exact: true }).click();
    const response = await pending;
    expect(response.ok(), await response.text()).toBeTruthy();
    id = uuid((await response.json()).id);
    await expect(page.getByText('Document ingested: authenticated.json')).toBeVisible();
    expect(token).toMatch(/^Bearer .+/);
    await page.goto('/');
    await page.getByPlaceholder('Search SBOMs...').fill(JSON.parse(data.toString()).metadata.component.name);
    await page.getByPlaceholder('Search SBOMs...').press('Tab');
    await expect(page.getByRole('row').filter({ hasText: JSON.parse(data.toString()).metadata.component.name })).toBeVisible();
    await page.reload();
    await expect(page.getByRole('row').filter({ hasText: JSON.parse(data.toString()).metadata.component.name })).toBeVisible();
  } finally {
    if (id && token) {
      const response = await request.delete(`${apiURL}/api/v3/sbom/urn:uuid:${id}`, { headers: { authorization: token } });
      expect(response.ok(), await response.text()).toBeTruthy();
    }
  }
});
