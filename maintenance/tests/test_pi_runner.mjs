import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { runBaseline } from "../.pi/extensions/tara-maintenance/runner.ts";

const maintenanceRoot = fileURLToPath(new URL("../", import.meta.url));
const taraPath = join(
	maintenanceRoot,
	"..",
	"shared",
	"reference-tara",
	"bbw",
	"reference-tara.json",
);
const architecturePath = join(
	maintenanceRoot,
	"..",
	"shared",
	"architecture",
	"bbw",
	"item-definition.json",
);
const changesPath = join(maintenanceRoot, "examples", "changes.json");

test("Pi runner evaluates the shared reference change set", async () => {
	const result = await runBaseline(
		{ taraPath, architecturePath, changesPath },
		maintenanceRoot,
	);

	assert.deepEqual(result.report.summary, {
		total: 4,
		review_required: 3,
		no_review: 0,
		unresolved: 1,
	});
	assert.equal(result.outputPath, undefined);
	assert.equal(JSON.parse(result.rendered).schema_version, "1.0");
});

test("Pi runner normalizes attachment prefixes and writes the requested report", async (t) => {
	const temporaryDirectory = await mkdtemp(join(maintenanceRoot, ".pi-runner-"));
	t.after(() => rm(temporaryDirectory, { recursive: true, force: true }));
	const result = await runBaseline(
		{
			taraPath: `@${taraPath}`,
			architecturePath: `@${architecturePath}`,
			changesPath: `@${changesPath}`,
			outputPath: "@report.json",
		},
		temporaryDirectory,
	);

	assert.equal(result.outputPath, join(temporaryDirectory, "report.json"));
	const savedReport = JSON.parse(await readFile(result.outputPath, "utf8"));
	assert.equal(savedReport.summary.total, 4);
});

test("Pi runner refuses report writes outside maintenance", async (t) => {
	const temporaryDirectory = await mkdtemp(join(tmpdir(), "tara-pi-runner-outside-"));
	t.after(() => rm(temporaryDirectory, { recursive: true, force: true }));
	const outputPath = join(temporaryDirectory, "report.json");

	for (const requestedOutputPath of [relative(maintenanceRoot, outputPath), outputPath]) {
		await assert.rejects(
			runBaseline(
				{ taraPath, architecturePath, changesPath, outputPath: requestedOutputPath },
				maintenanceRoot,
			),
			/output_path must stay within maintenance/,
		);
	}
	await assert.rejects(readFile(outputPath, "utf8"), { code: "ENOENT" });
});

test("Pi runner surfaces baseline input errors", async () => {
	await assert.rejects(
		runBaseline(
			{
				taraPath,
				architecturePath,
				changesPath: join(maintenanceRoot, "examples", "missing.json"),
			},
			maintenanceRoot,
		),
		/TARA maintenance failed: .*Cannot load JSON/,
	);
});

test("Pi runner inherits artifact paths from the selected config", async () => {
	const result = await runBaseline(
		{
			configPath: join(maintenanceRoot, "config", "maintenance.example.json"),
			changesPath,
		},
		maintenanceRoot,
	);

	assert.equal(result.report.summary.total, 4);
	assert.equal(result.outputPath, undefined);
});
