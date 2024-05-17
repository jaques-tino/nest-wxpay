import { join } from 'path'
import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  outDir: join(__dirname, './build'),
  dts: true,
  splitting: false,
  sourcemap: false,
  clean: true,
  tsconfig: 'tsconfig.json'
})
