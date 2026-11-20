import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { runBaseline } from "../.pi/extensions/tara-maintenance/runner.ts";

const maintenanceRoot = fileURLToPath(new URL("../", import.meta.url));
const referenceDirectory = join(maintenanceRoot, "..", "shared", "reference-tara");
const taraPath = join(
	referenceDirectory,
	"TARA_AUTO_BBW_01_Attack_Trees_and_Risk_Treatment.json",
);
const architecturePath = join(
	referenceDirectory,
	"Electronic_Brake-by-Wire_(BBW)_&_Regenerative_Braking_Subsystem.json",
);
const changesPath = join(maintenanceRoot, "examples", "changes.json");

test("Pi runner evaluates the shared reference change set", async () => {
	const result = await runBaseline(
		{ taraPath, architecturePath, changesPath },
		maintenanceRoot,
	);

	assert.deepEqual(result.report.summary, {
		total: 4,
		review_required: 2,
		no_review: 1,
		unresolved: 1,
	});
	assert.equal(result.outputPath, undefined);
	assert.equal(JSON.parse(result.rendered).schema_version, "1.0");
});

test("Pi runner normalizes attachment prefixes and writes the requested report", async () => {
	const temporaryDirectory = await mkdtemp(join(tmpdir(), "tara-pi-runner-"));
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
