import { closeSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { registerHooks } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

// `approved` is prepended by the native helper as JSON. Never reopen the
// original entry path to get its source, even after Node resolves the URL.
const entryURL = pathToFileURL(approved.path).href;
if (process.versions.node.split(".")[0] !== "26") {
  throw new Error("node_entry_version_unsupported");
}
const source = readFileSync(approved.fd);
closeSync(approved.fd);
if (createHash("sha256").update(source).digest("hex") !== approved.sha) {
  throw new Error("approved_entry_bytes_mismatch");
}
registerHooks({
  resolve(specifier, context, next) {
    if (!context.parentURL && specifier.startsWith("file:") && fileURLToPath(specifier) === approved.path) {
      process.argv[1] = approved.path;
      return { url: entryURL, format: "module", shortCircuit: true };
    }
    return next(specifier, context);
  },
  load(url, context, next) {
    if (url === entryURL) return { format: "module", source, shortCircuit: true };
    return next(url, context);
  }
});
