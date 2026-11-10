import { test, expect, freshSbom, apiURL, uuid, navigate } from '../support';

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

test('user menu logs out, stays logged out after reload, and allows login again', async ({ page }) => {
  await page.goto('/');
  const menu = page.getByRole('button', { name: 'User menu', exact: true });
  await expect(menu).toBeVisible();
  await expect(page.locator('header .pf-v6-c-toolbar__group.pf-m-align-end').getByRole('button', { name: 'User menu', exact: true })).toBeVisible();
  const rightGap = await menu.evaluate(element => {
    const header = element.closest('header')!.getBoundingClientRect();
    return header.right - element.getBoundingClientRect().right;
  });
  expect(rightGap).toBeLessThan(48);
  await page.getByRole('button', { name: 'User menu', exact: true }).click();
  await page.getByRole('menuitem', { name: 'Log out', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Log in', exact: true })).toBeVisible();
  await expect(page.getByPlaceholder('Search SBOMs...')).toHaveCount(0);
  await page.reload();
  await expect(page.getByRole('button', { name: 'Log in', exact: true })).toBeVisible();
  const authorization = page.waitForRequest(r => r.url().includes('response_type=code'));
  await page.getByRole('button', { name: 'Log in', exact: true }).click();
  await authorization;
  await expect(page.getByPlaceholder('Search SBOMs...')).toBeVisible();
  await expect(page.getByRole('button', { name: 'User menu', exact: true })).toBeVisible();
});

for (const kind of ['read', 'json', 'upload'] as const) {
  test(`a rejected ${kind} request ends the session and allows login again`, async ({ page, allowedApiErrors }) => {
    await page.goto('/');
    await expect(page.getByRole('button', { name: 'User menu', exact: true })).toBeVisible();
    const path = kind === 'read' ? '/api/v3/sbom' : kind === 'json' ? '/api/v3/upload/from-url' : '/api/v3/upload';
    allowedApiErrors.push(path);
    await page.route(`**${path}${kind === 'read' ? '?**' : ''}`, route => route.fulfill({ status: 401, body: 'Token rejected' }), { times: 1 });
    if (kind === 'read') {
      await page.getByPlaceholder('Search SBOMs...').fill('expired-session');
    } else {
      await navigate(page, 'Ingest');
      if (kind === 'json') {
        await page.getByRole('button', { name: 'From URL', exact: true }).click();
        await page.getByPlaceholder('https://example.com/document.json').fill('https://example.com/document.json');
        await page.getByRole('button', { name: 'Ingest', exact: true }).click();
      } else {
        await page.locator('input[type=file]').setInputFiles({ name: 'rejected.json', mimeType: 'application/json', buffer: await freshSbom() });
        await page.getByRole('button', { name: 'Upload', exact: true }).click();
      }
    }
    await expect(page.getByRole('button', { name: 'Log in', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'User menu', exact: true })).toHaveCount(0);
    await page.getByRole('button', { name: 'Log in', exact: true }).click();
    await expect(page.getByRole('button', { name: 'User menu', exact: true })).toBeVisible();
    await expect(page.getByPlaceholder('Search SBOMs...')).toBeVisible();
  });
}

for (const status of [403, 503]) {
  test(`HTTP ${status} keeps the authenticated session`, async ({ page, allowedApiErrors }) => {
    allowedApiErrors.push('/api/v3/sbom');
    await page.route('**/api/v3/sbom?**', route => route.fulfill({ status, body: 'Request failed' }), { times: 1 });
    await page.goto('/');
    await expect(page.getByText('Failed to load SBOMs')).toBeVisible();
    await expect(page.getByRole('button', { name: 'User menu', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Log in', exact: true })).toHaveCount(0);
  });
}
