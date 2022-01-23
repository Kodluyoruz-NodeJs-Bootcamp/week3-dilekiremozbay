import type { Options } from "tsup";

export const tsup: Options = {
  splitting: false,
  sourcemap: true,
  clean: false,
  target: "node16",
  entryPoints: ["src/app.ts"],
  format: ["esm"],
  skipNodeModulesBundle: true,
  outDir: "build",
};
