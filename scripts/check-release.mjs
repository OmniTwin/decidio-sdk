#!/usr/bin/env node
// Checks the packages built in this repository against release.json before anything is published:
// every npm package must pack exactly the listed files with the listed SHA-256, and the Python build
// directory must hold one wheel and one sdist with exactly the listed members.
//   node scripts/check-release.mjs [--py-dist <dir>]
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(import.meta.url), "..", "..");
const args = process.argv.slice(2);
const pyDistArg = args.includes("--py-dist") ? args[args.indexOf("--py-dist") + 1] : null;
const release = JSON.parse(readFileSync(join(root, "release.json"), "utf8"));
const WIN = process.platform === "win32";
const problems = [];

const run = (cmd, argv, cwd) => {
  const r = WIN && cmd === "npm"
    ? spawnSync(`npm ${argv.join(" ")}`, { encoding: "utf8", shell: true, cwd })
    : spawnSync(cmd, argv, { encoding: "utf8", cwd });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`${cmd} ${argv.join(" ")} failed in ${cwd}:\n${r.stderr}`);
  return r.stdout;
};
const sha = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");
const same = (a, b) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());

for (const [name, pkg] of Object.entries(release.npm)) {
  const dir = join(root, pkg.dir);
  const packed = JSON.parse(run("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], dir))[0].files.map((f) => f.path);
  const want = Object.keys(pkg.files);
  if (!same(packed, want)) {
    problems.push(`${name}: the pack holds ${packed.filter((f) => !want.includes(f)).join(", ") || "nothing extra"} beyond release.json and lacks ${want.filter((f) => !packed.includes(f)).join(", ") || "nothing"}`);
    continue;
  }
  for (const f of want) if (sha(join(dir, f)) !== pkg.files[f]) problems.push(`${name}: ${f} differs from the approved build`);
}

if (release.pypi) {
  const dist = resolve(root, pyDistArg ?? release.pypi.dist);
  const names = readdirSync(dist);
  const wheel = names.find((n) => n.endsWith(".whl"));
  const sdist = names.find((n) => n.endsWith(".tar.gz"));
  if (names.length !== 2 || !wheel || !sdist) problems.push(`${dist} must hold exactly one wheel and one sdist (holds ${names.join(", ") || "nothing"})`);
  else {
    const members = (file) => run(process.env.PYTHON ?? "python", ["-c", [
      "import sys, zipfile, tarfile",
      "p = sys.argv[1]",
      "n = zipfile.ZipFile(p).namelist() if p.endswith('.whl') else [m.name for m in tarfile.open(p).getmembers() if m.isfile()]",
      "print('\\n'.join(sorted(n)))",
    ].join("\n"), file], root).split(/\r?\n/).filter(Boolean);
    if (!same(members(join(dist, wheel)), release.pypi.wheel)) problems.push(`the wheel's members differ from release.json`);
    if (!same(members(join(dist, sdist)), release.pypi.sdist)) problems.push(`the sdist's members differ from release.json`);
  }
}

if (problems.length) {
  for (const p of problems) console.error(`  ✗ ${p}`);
  console.error(`check-release: ${problems.length} problem${problems.length === 1 ? "" : "s"}; nothing may be published.`);
  process.exit(1);
}
console.log(`check-release: ${Object.keys(release.npm).length} npm package${Object.keys(release.npm).length === 1 ? "" : "s"}${release.pypi ? " and the Python wheel and sdist" : ""} match release.json.`);
