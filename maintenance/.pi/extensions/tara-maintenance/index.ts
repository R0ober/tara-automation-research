import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	DEFAULT_MAX_BYTES,
	DEFAULT_MAX_LINES,
	formatSize,
	truncateHead,
	withFileMutationQueue,
	type ExtensionAPI,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { absolutePath, resolveConfigPath, resolveOutputPath, runBaseline } from "./runner.ts";

interface MaintenanceDetails {
	summary: unknown;
	outputPath?: string;
	truncated: boolean;
}

const PATH_FIELDS: Record<string, true> = {
	tara_path: true,
	architecture_path: true,
	changes_path: true,
	output_path: true,
};

function invocationSignature(input: Record<string, unknown>, cwd: string): string {
	const normalized = Object.entries(input)
		.sort(([left], [right]) => left.localeCompare(right))
		.map(([key, value]) => {
			if (typeof value !== "string") return [key, value];
			if (key === "config_path") return [key, resolveConfigPath(value)];
			if (PATH_FIELDS[key]) return [key, absolutePath(value, cwd)];
			return [key, value];
		});
	return JSON.stringify(normalized);
}

export default function taraMaintenance(pi: ExtensionAPI) {
	const pendingInvocations = new Set<string>();
	const temporaryDirectories = new Set<string>();

	pi.on("session_start", () => {
		pendingInvocations.clear();
	});
	pi.on("session_shutdown", async () => {
		await Promise.all(
			[...temporaryDirectories].map((directory) =>
				rm(directory, { recursive: true, force: true }),
			),
		);
		temporaryDirectories.clear();
	});
	pi.on("tool_call", (event, ctx) => {
		if (event.toolName !== "tara_maintenance") return;
		const signature = invocationSignature(event.input, ctx.cwd);
		if (pendingInvocations.has(signature)) {
			return {
				block: true,
				reason: "This identical TARA analysis is already running. Wait for its tool result.",
			};
		}
	});

	pi.registerTool({
		name: "tara_maintenance",
		label: "TARA maintenance",
		description:
			"Evaluate vulnerability and component-change JSON against an existing TARA and item architecture. Returns deterministic review_required, no_review, or unresolved decisions with evidence. Supports exact/wildcard CPEs and numeric version ranges; does not fetch feeds or update risk ratings.",
		promptSnippet: "Triage TARA vulnerability and component changes with inspectable evidence",
		promptGuidelines: [
			"Use tara_maintenance when the user asks whether new vulnerabilities or component changes require review of an existing TARA.",
			"Preserve tara_maintenance decisions verbatim; do not reclassify unresolved cases as no_review or invent missing applicability evidence.",
			"When presenting tara_maintenance results, identify the matched components, existing attack steps, or missing mappings that support each recommendation.",
		],
		parameters: Type.Object(
			{
				config_path: Type.Optional(
					Type.String({ description: "Optional maintenance configuration JSON path" }),
				),
				tara_path: Type.Optional(Type.String({ description: "Overrides configured TARA JSON path" })),
				architecture_path: Type.Optional(
					Type.String({ description: "Overrides configured item architecture JSON path" }),
				),
				changes_path: Type.Optional(
					Type.String({ description: "Overrides configured vulnerability/component change JSON path" }),
				),
				output_path: Type.Optional(
					Type.String({ description: "Optional report path within maintenance/" }),
				),
			},
			{ additionalProperties: false },
		),

		async execute(_toolCallId, params, signal, _onUpdate, ctx) {
			const signature = invocationSignature(params, ctx.cwd);
			if (pendingInvocations.has(signature)) {
				throw new Error("This identical TARA analysis is already running");
			}
			pendingInvocations.add(signature);
			try {
				const absoluteOutputPath = params.output_path
					? resolveOutputPath(params.output_path, ctx.cwd)
					: undefined;
				const paths = {
					configPath: params.config_path,
					taraPath: params.tara_path,
					architecturePath: params.architecture_path,
					changesPath: params.changes_path,
					outputPath: absoluteOutputPath,
				};
				const run = () => runBaseline(paths, ctx.cwd, signal);
				const result = absoluteOutputPath
					? await withFileMutationQueue(absoluteOutputPath, run)
					: await run();

				const truncation = truncateHead(result.rendered, {
					maxLines: DEFAULT_MAX_LINES,
					maxBytes: DEFAULT_MAX_BYTES,
				});
				let outputPath = result.outputPath;
				if (truncation.truncated && !outputPath) {
					const temporaryDirectory = await mkdtemp(join(tmpdir(), "tara-maintenance-"));
					temporaryDirectories.add(temporaryDirectory);
					outputPath = join(temporaryDirectory, "report.json");
					await writeFile(outputPath, result.rendered, "utf8");
				}

				let text = truncation.content;
				if (truncation.truncated) {
					text +=
						`\n\n[Report truncated to ${truncation.outputLines} lines and ` +
						`${formatSize(truncation.outputBytes)}. Complete report: ${outputPath}]`;
				} else if (outputPath) {
					text += `\n\n[Complete report: ${outputPath}]`;
				}
				const details: MaintenanceDetails = {
					summary: result.report.summary,
					outputPath,
					truncated: truncation.truncated,
				};
				return {
					content: [{ type: "text", text }],
					details,
				};
			} finally {
				pendingInvocations.delete(signature);
			}
		},
	});
}
