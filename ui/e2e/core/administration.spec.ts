import { randomUUID } from 'node:crypto';
import { test, expect, apiURL } from '../support';

test('correlation options validate, create, update, persist, and delete', async ({ page, request, owned, seed }) => {
  const publisher = `https://${randomUUID()}.example.test`;
  await page.goto('/options');
  await page.getByRole('button', { name: 'Add option', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByRole('button', { name: 'Add', exact: true })).toBeDisabled();
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await page.getByRole('button', { name: 'Add option', exact: true }).click();
  await dialog.getByPlaceholder('https://www.example.com').fill(publisher);
  await dialog.getByPlaceholder('Why the option is set, shown with the evidence').fill('e2e option');
  const created = page.waitForResponse(r => r.url().endsWith('/correlation/option') && r.request().method() === 'POST');
  await dialog.getByRole('button', { name: 'Add', exact: true }).click();
  const response = await created;
  expect(response.ok(), await response.text()).toBeTruthy();
  owned.options.push((await response.json()).id);
  const row = page.getByRole('row').filter({ hasText: publisher });
  await expect(row).toContainText('e2e option');
  const toggle = row.getByRole('checkbox', { name: 'Enabled' });
  const checked = await toggle.isChecked();
  const updated = page.waitForResponse(r => r.url().includes('/correlation/option/') && r.request().method() === 'PUT');
  await toggle.focus();
  await toggle.press('Space');
  expect((await updated).ok()).toBeTruthy();
  await page.reload();
  await expect(toggle).toBeChecked({ checked: !checked });
  await row.getByRole('button', { name: 'Delete', exact: true }).click();
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: 'Delete', exact: true }).click();
  await dialog.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(row).toHaveCount(0);
});

test('provider aliases validate, edit, persist, and delete', async ({ page, owned, seed }) => {
  const provider = `e2e-${randomUUID()}`;
  await page.goto('/provideraliases');
  await page.getByRole('button', { name: 'Add provider alias', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('textbox', { name: 'Canonical provider', exact: true }).fill(provider);
  await dialog.getByRole('textbox', { name: 'Aliases (one per line)', exact: true }).fill('invalid-prefix:value');
  await dialog.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(dialog.getByText('Unable to save')).toBeVisible();
  await dialog.getByRole('textbox', { name: 'Aliases (one per line)', exact: true }).fill(`name:${provider}`);
  const created = page.waitForResponse(r => r.url().endsWith('/correlation/provider-alias') && r.request().method() === 'POST');
  await dialog.getByRole('button', { name: 'Save', exact: true }).click();
  const response = await created;
  expect(response.ok(), await response.text()).toBeTruthy();
  owned.aliases.push((await response.json()).id);
  await expect(dialog).toHaveCount(0);
  await page.getByRole('button', { name: `Edit aliases for ${provider}`, exact: true }).click();
  await dialog.getByRole('textbox', { name: 'Aliases (one per line)', exact: true }).fill(`name:${provider}\ndistro:${provider}`);
  await dialog.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await page.reload();
  const row = page.getByRole('row').filter({ has: page.getByText(provider).first() });
  await expect(row).toContainText('Distribution');
  await page.getByRole('button', { name: `Delete aliases for ${provider}`, exact: true }).click();
  await dialog.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByRole('button', { name: `Edit aliases for ${provider}`, exact: true })).toHaveCount(0);
});

test('freshness filtering and durable refresh complete after settings change', async ({ page, request, owned, seed }) => {
  test.setTimeout(120_000);
  // A dedicated publisher avoids changing interpretation of the baseline advisories.
  const created = await request.post(`${apiURL}/api/v3/correlation/option`, { data: {
    key: 'versionless_purl', publisher_namespace: `https://${randomUUID()}.example.test`, value: true,
  } });
  expect(created.ok(), await created.text()).toBeTruthy();
  owned.options.push((await created.json()).id);
  await page.goto('/correlationstatus');
  const refresh = page.getByRole('button', { name: 'Refresh outdated results', exact: true });
  await expect(refresh).toBeEnabled({ timeout: 60_000 });
  const pending = page.waitForResponse(r => r.url().endsWith('/correlation/refresh') && r.request().method() === 'POST');
  await refresh.click();
  const response = await pending;
  expect(response.ok()).toBeTruthy();
  const job = await response.json();
  await expect.poll(async () => {
    const response = await request.get(`${apiURL}/api/v3/correlation/refresh/${job.id}`);
    return (await response.json()).job.status;
  }, { timeout: 90_000 }).toBe('completed');
  await expect(page.getByRole('progressbar', { name: 'No refresh running', exact: true })).toBeVisible({ timeout: 30_000 });
  await page.getByRole('button', { name: 'Current', exact: true }).click();
  await expect(page.getByRole('row').filter({ hasText: 's6-urllib3-affected' })).toContainText('Current');
  await page.getByRole('button', { name: 'Needs refreshing', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'No documents found', exact: true })).toBeVisible();
});
