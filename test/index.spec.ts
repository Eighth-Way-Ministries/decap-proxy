import { SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';

describe('GET /', () => {
  it('responds with 404', async () => {
    const response = await SELF.fetch('https://example.com/');
    expect(response.status).toBe(404);
    expect(await response.text()).toBe('Not found');
  });
});

describe('GET /auth', () => {
  it('redirects to GitHub authorize URL', async () => {
    const response = await SELF.fetch('https://example.com/auth', { redirect: 'manual' });
    expect(response.status).toBe(302);
    const location = response.headers.get('location');
    expect(location).toMatch(/https:\/\/github.com\/login\/oauth\/authorize/);
    const cookie = response.headers.get('set-cookie');
    expect(cookie).toMatch(/decap_oauth_state=/);
  });
});
