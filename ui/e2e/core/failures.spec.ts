import { test, expect } from '../support';

test('discovery failure is visible without mounting application pages', async ({ page, allowedApiErrors }) => {
  allowedApiErrors.push('/.well-known/trustify');
  await page.route('**/.well-known/trustify', route => route.fulfill({ status: 503, body: 'Unavailable' }));
  await page.goto('/');
  await expect(page.getByText('Failed to connect')).toBeVisible();
  await expect(page.getByPlaceholder('Search SBOMs...')).toHaveCount(0);
});

test('list API failure can recover after a reload', async ({ page, allowedApiErrors }) => {
  allowedApiErrors.push('/api/v3/sbom');
  await page.route('**/api/v3/sbom?**', route => route.fulfill({ status: 503, body: 'Unavailable' }), { times: 1 });
  await page.goto('/');
  await expect(page.getByText('Failed to load SBOMs')).toBeVisible();
  await page.reload();
  await expect(page.getByPlaceholder('Search SBOMs...')).toBeVisible();
  await expect(page.getByText('Failed to load SBOMs')).toHaveCount(0);
});

test('network failure displays an actionable query error', async ({ page, allowedApiErrors }) => {
  allowedApiErrors.push('/api/v3/correlation/query');
  await page.route('**/api/v3/correlation/query?**', route => route.abort('failed'));
  await page.goto('/query');
  await page.getByPlaceholder('Enter identifier value').fill('e2e-network-error');
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await expect(page.getByText('Query failed')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Search', exact: true })).toBeEnabled();
});

test('missing advisory displays an error without panicking', async ({ page, allowedApiErrors }) => {
  allowedApiErrors.push('/api/v3/advisory/urn:uuid:00000000-0000-4000-8000-000000000000');
  allowedApiErrors.push('/api/v3/advisory/urn:uuid:00000000-0000-4000-8000-000000000000/download');
  await page.goto('/advisory/00000000-0000-4000-8000-000000000000');
  await expect(page.getByText('Failed to load advisory')).toBeVisible();
});
