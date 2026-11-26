import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { registerHooks } from "node:module";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const maintenanceRoot = fileURLToPath(new URL("../", import.meta.url));
const piRuntime = `
export const DEFAULT_MAX_LINES = 4;
export const DEFAULT_MAX_BYTES = 256;
export function formatSize(bytes) { return bytes + " B"; }
export function truncateHead(content, limits) {
	const lines = content.split("\\n");
	if (lines.length <= limits.maxLines && Buffer.byteLength(content) <= limits.maxBytes) {
		return { content, truncated: false };
	}
	const outputLines = Math.min(limits.maxLines, lines.length);
	const truncated = lines.slice(0, outputLines).join("\\n");
	return {
		content: truncated,
		truncated: true,
		outputLines,
		outputBytes: Buffer.byteLength(truncated),
	};
}
export function withFileMutationQueue(_path, run) { return run(); }
`;
const typeboxRuntime = `
const identity = (value) => value;
export const Type = { Object: identity, Optional: identity, String: identity };
`;

registerHooks({
	resolve(specifier, context, nextResolve) {
		if (specifier === "@earendil-works/pi-coding-agent") {
			return {
				url: `data:text/javascript,${encodeURIComponent(piRuntime)}`,
				shortCircuit: true,
			};
		}
		if (specifier === "typebox") {
			return {
				url: `data:text/javascript,${encodeURIComponent(typeboxRuntime)}`,
				shortCircuit: true,
			};
		}
		return nextResolve(specifier, context);
	},
});

const { default: taraMaintenance } = await import(
	"../.pi/extensions/tara-maintenance/index.ts"
);

function createExtension() {
	const handlers = {};
	let tool;
	const pi = {
		on(event, handler) {
			handlers[event] = handler;
		},
		registerTool(definition) {
			tool = definition;
		},
	};
	taraMaintenance(pi);
	const context = { cwd: maintenanceRoot };
	return {
		call(input) {
			return handlers.tool_call({ toolName: "tara_maintenance", input }, context);
		},
		execute(input) {
			return tool.execute("tool-call", input, undefined, undefined, context);
		},
		shutdown() {
			return handlers.session_shutdown({}, context);
		},
	};
}

const parameters = {
	config_path: "config/maintenance.example.json",
	changes_path: "examples/changes.json",
};

test("Pi extension permits identical calls after successful completion", async (t) => {
	const extension = createExtension();
	t.after(() => extension.shutdown());

	assert.equal(extension.call(parameters), undefined);
	const first = await extension.execute(parameters);
	assert.equal(first.details.summary.total, 4);
	assert.equal(extension.call(parameters), undefined);
	const second = await extension.execute(parameters);
	assert.equal(second.details.summary.total, 4);
});

test("Pi extension deduplicates only running calls and canonicalizes paths", async (t) => {
	const extension = createExtension();
	const temporaryDirectory = await mkdtemp(join(maintenanceRoot, ".pi-index-"));
	t.after(async () => {
		await extension.shutdown();
		await rm(temporaryDirectory, { recursive: true, force: true });
	});
	const outputPath = join(temporaryDirectory, "report.json");
	const unaliased = { ...parameters, output_path: outputPath };
	const aliased = {
		config_path: "@config/maintenance.example.json",
		changes_path: "@examples/changes.json",
		output_path: `@${outputPath}`,
	};

	assert.equal(extension.call(aliased), undefined);
	const running = extension.execute(aliased);
	assert.equal(extension.call(unaliased)?.block, true);
	await running;
	assert.equal(JSON.parse(await readFile(outputPath, "utf8")).summary.total, 4);
	assert.equal(extension.call(unaliased), undefined);

	// A later handler may block this accepted call before execute starts.
	assert.equal(extension.call(unaliased), undefined);
	assert.equal(extension.call(unaliased), undefined);
});

test("Pi extension removes truncated report directories on shutdown", async (t) => {
	const extension = createExtension();
	t.after(() => extension.shutdown());

	const result = await extension.execute(parameters);
	assert.equal(result.details.truncated, true);
	const reportPath = result.details.outputPath;
	assert.equal(JSON.parse(await readFile(reportPath, "utf8")).summary.total, 4);

	await extension.shutdown();
	await assert.rejects(readFile(reportPath, "utf8"), { code: "ENOENT" });
});
