import {
    Application,
    Config,
    Delegate,
    Operation,
    LogLevel,
    Target,
    TargetDevice,
    TargetProcess,
} from "../lib/index.js";

import chalk, { ChalkInstance } from "chalk";
import { program, Command } from "commander";
import prettyHrtime from "pretty-hrtime";

async function main(): Promise<void> {
    const args = parseArguments();

    const config: Config = {
        targets: args.targets,
    };
    const ui = new ConsoleUI();

    const app = new Application(config, ui);

    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);

    try {
        await app.run();
    } catch (error) {
        process.exitCode = 1;
        const e = error as Error;
        process.stderr.write(`${chalk.redBright(e.stack)}\n`);
    } finally {
        stop();
    }

    function stop() {
        app.dispose();
    }
}

class ConsoleUI implements Delegate {
    #pendingOperation: PendingOperation | null = null;

    public onProgress(operation: Operation): void {
        const pending = {
            operation: operation,
            logMessageCount: 0,
        };
        this.#pendingOperation = pending;

        operation.onceComplete(() => {
            if (pending.logMessageCount > 0) {
                process.stdout.write(`[${operation.scope}] ${chalk.cyan(`${operation.description} completed`)}\n`);
            }

            process.stdout.write(`[${operation.scope}] ${chalk.cyan(operation.description)} ${chalk.gray(prettyHrtime(operation.elapsed))}\n`);

            this.#pendingOperation = null;
        });
    }

    public onConsoleMessage(scope: string, level: LogLevel, text: string): void {
        let c: ChalkInstance;
        switch (level) {
            case "info":
                c = chalk.whiteBright;
                break;
            case "warning":
                c = chalk.yellowBright;
                break;
            case "error":
                c = chalk.redBright;
                break;
            default:
                c = chalk.grey;
        }

        const pending = this.#pendingOperation;
        if (pending !== null) {
            if (pending.logMessageCount === 0) {
                process.stdout.write(`${chalk.gray("...")}\n`);
            }

            pending.logMessageCount += 1;
        }

        process.stdout.write(`[${scope}] ${c(text)}\n`);
    }
}

interface PendingOperation {
    operation: Operation;
    logMessageCount: number;
}

interface Arguments {
    targets: Target[];
}

function parseArguments(): Arguments {
    const targets: Target[] = [];

    program
        .option("-U, --usb", "Connect to USB device", () => {
            openNewTarget({ kind: "usb" });
        })
        .option("-R, --remote", "Connect to remote frida-server", () => {
            openNewTarget({
                kind: "remote"
            });
        })
        .option("-H --host [HOST]", "Connect to remote frida-server by host", (host: string) => {
            openNewTarget({
                kind: "by-host",
                host: host
            });
        })
        .option("-D, --device [ID]", "Connect to device with the given ID", (id: string) => {
            openNewTarget({
                kind: "by-id",
                id: id
            });
        })
        .option("-f, --file [FILE]", "Spawn FILE", (file: string) => {
            addTargetProcess({
                kind: "spawn",
                program: file
            });
        })
        .option("-n, --attach-name [NAME]", "Attach to NAME", (name: string) => {
            addTargetProcess({
                kind: "by-name",
                name: name
            });
        })
        .option("-a, --all-by-name [NAME]", "Attach to all processes named NAME", (name: string) => {
            addTargetProcess({
                kind: "all-by-name",
                name: name
            });
        })
        .option("-1, --any-by-name [NAME]", "Attach to any process named NAME", (name: string) => {
            addTargetProcess({
                kind: "any-by-name",
                name: name
            });
        })
        .option("-p, --attach-pid [PID]", "Attach to PID", (id: string) => {
            const pid = parseInt(id, 10);
            addTargetProcess({
                kind: "by-ids",
                ids: [pid]
            });
        })
        .option("-F, --attach-frontmost", "attach to frontmost application", () => {
            addTargetProcess({
                kind: "by-frontmost"
            });
        })
        .option("-w, --wait [NAME]", "Attach to NAME as soon as it's spawned", (name: string) => {
            addTargetProcess({
                kind: "by-gating",
                name: name
            });
        })
        .parse(process.argv);

    if (process.argv.length < 3) {
        program.help();
    }

    const numTargetProcesses = targets.reduce((total, target) => total + target.processes.length, 0);
    if (numTargetProcesses === 0) {
        addTargetProcess(inferTargetProcess(program));
    }

    function openNewTarget(device: TargetDevice): Target {
        const target: Target = {
            device,
            processes: []
        };
        targets.push(target);
        return target;
    }

    function addTargetProcess(process: TargetProcess) {
        const target = (targets.length !== 0)
            ? targets[targets.length - 1]
            : openNewTarget({ kind: "local" });

        if (process.kind === "by-ids") {
            const processes = target.processes;
            const previous = processes[processes.length - 1];
            if (previous?.kind === "by-ids") {
                previous.ids.push(...process.ids);
                return;
            }
        }

        target.processes.push(process);
    }

    return {
        targets,
    };
}

function inferTargetProcess(prog: Command): TargetProcess {
    const spec = prog.args[0];
    if (spec === undefined) {
        throw new Error("Expected a target");
    }

    const potentialPid = parseInt(spec, 10);
    if (!isNaN(potentialPid)) {
        return {
            kind: "by-ids",
            ids: [potentialPid]
        }
    }

    return {
        kind: "by-name",
        name: spec
    };
}

main();
