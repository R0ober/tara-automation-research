import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { delimiter, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export interface BaselinePaths {
	configPath?: string;
	taraPath?: string;
	architecturePath?: string;
	changesPath?: string;
	outputPath?: string;
}

export interface BaselineResult {
	report: Record<string, unknown>;
	rendered: string;
	outputPath?: string;
}

const maintenanceRoot = fileURLToPath(new URL("../../../", import.meta.url));
const INHERITED_ENVIRONMENT_VARIABLES = [
	"PATH",
	"HOME",
	"USERPROFILE",
	"HOMEDRIVE",
	"HOMEPATH",
	"LANG",
	"LC_ALL",
	"TMPDIR",
	"TEMP",
	"TMP",
	"SystemRoot",
	"WINDIR",
	"COMSPEC",
	"PATHEXT",
] as const;

export function absolutePath(path: string, cwd: string): string {
	const withoutAttachmentPrefix = path.startsWith("@") ? path.slice(1) : path;
	return resolve(cwd, withoutAttachmentPrefix);
}

export function resolveConfigPath(path: string): string {
	return absolutePath(path, maintenanceRoot);
}

export function resolveOutputPath(path: string, cwd: string): string {
	const outputPath = absolutePath(path, cwd);
	const relativeToMaintenance = relative(maintenanceRoot, outputPath);
	if (
		relativeToMaintenance === ".." ||
		relativeToMaintenance.startsWith(`..${sep}`) ||
		isAbsolute(relativeToMaintenance)
	) {
		throw new Error("TARA maintenance output_path must stay within maintenance/");
	}
	return outputPath;
}

/** Run the single Python implementation without invoking a shell. */
export async function runBaseline(
	paths: BaselinePaths,
	cwd: string,
	signal?: AbortSignal,
): Promise<BaselineResult> {
	const args = ["-m", "tara_maintenance"];
	const configuredPath = paths.configPath || process.env.TARA_MAINTENANCE_CONFIG;
	const defaultConfigPath = resolve(maintenanceRoot, "config/maintenance.json");
	if (configuredPath) {
		args.push("--config", resolveConfigPath(configuredPath));
	} else if (existsSync(defaultConfigPath)) {
		args.push("--config", defaultConfigPath);
	}
	const inputArguments = [
		["--tara", paths.taraPath],
		["--architecture", paths.architecturePath],
		["--changes", paths.changesPath],
	] as const;
	for (const [flag, path] of inputArguments) {
		if (path) args.push(flag, absolutePath(path, cwd));
	}
	const outputPath = paths.outputPath
		? resolveOutputPath(paths.outputPath, cwd)
		: undefined;
	if (outputPath) args.push("--output", outputPath);
	else args.push("--stdout");

	const sourceDirectory = resolve(maintenanceRoot, "src");
	const pythonPath = [sourceDirectory, process.env.PYTHONPATH]
		.filter(Boolean)
		.join(delimiter);
	const environment: NodeJS.ProcessEnv = { PYTHONPATH: pythonPath };
	for (const name of INHERITED_ENVIRONMENT_VARIABLES) {
		const value = process.env[name];
		if (value !== undefined) environment[name] = value;
	}
	const { promise, resolve: resolveProcess, reject } = Promise.withResolvers<{
		stdout: string;
		stderr: string;
	}>();
	const virtualEnvironmentPython = resolve(
		maintenanceRoot,
		process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python",
	);
	execFile(
		process.env.PYTHON ||
			(existsSync(virtualEnvironmentPython) ? virtualEnvironmentPython : "python3"),
		args,
		{
			cwd: maintenanceRoot,
			env: environment,
			encoding: "utf8",
			maxBuffer: 16 * 1024 * 1024,
			signal,
		},
		(error, stdout, stderr) => {
			if (error) {
				const details = stderr.trim() || error.message;
				reject(new Error(`TARA maintenance failed: ${details}`, { cause: error }));
				return;
			}
			resolveProcess({ stdout, stderr });
		},
	);
	const { stdout } = await promise;

	const rendered = outputPath ? await readFile(outputPath, "utf8") : stdout;
	return {
		report: JSON.parse(rendered) as Record<string, unknown>,
		rendered,
		outputPath,
	};
}
