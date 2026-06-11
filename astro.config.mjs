import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://blackoutsecure.github.io',
  base: '/shadow-ai-hunting',
  output: 'static',
  build: {
    format: 'file'
  },
  markdown: {
    shikiConfig: {
      theme: 'github-dark',
      wrap: true
    }
  }
});
