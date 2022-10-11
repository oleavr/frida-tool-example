import {
    Application,
    Config,
    Delegate,
    Operation,
    LogLevel,
    TargetDevice,
    TargetProcess,
} from "../lib/index.js";

import chalk, { ChalkInstance } from "chalk";
import { program, Command } from "commander";
import prettyHrtime from "pretty-hrtime";

async function main(): Promise<void> {
    const apps: Application[] = [];

    try {
        const args = parseArguments();
        const ui = new ConsoleUI();

        for (const targetDevice of args.targetDevices) {
            const config: Config = {
                targetDevice,
                targetProcess: args.targetProcess
            };
            apps.push(new Application(config, ui));
        }

        process.on("SIGINT", stop);
        process.on("SIGTERM", stop);

        await Promise.all(apps.map(a => a.run()));
    } catch (error) {
        process.exitCode = 1;
        let e = error as Error;
        process.stderr.write(`${chalk.redBright(e.stack)}\n`);
    } finally {
        stop();
    }

    function stop() {
        for (let app of apps) {
            app.dispose();
        }
    }
}

class ConsoleUI implements Delegate {
    private pendingOperation: PendingOperation | null = null;

    public onProgress(operation: Operation): void {
        const pending = {
            operation: operation,
            logMessageCount: 0,
        };
        this.pendingOperation = pending;

        operation.onceComplete(() => {
            if (pending.logMessageCount > 0) {
                process.stdout.write(`[${operation.scope}] ${chalk.cyan(`${operation.description} completed`)}\n`);
            }

            process.stdout.write(`[${operation.scope}] ${chalk.cyan(operation.description)} ${chalk.gray(prettyHrtime(operation.elapsed))}\n`);

            this.pendingOperation = null;
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

        const pending = this.pendingOperation;
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
    targetDevices: TargetDevice[];
    targetProcess: TargetProcess;
}

function parseArguments(): Arguments {
    const targetDevices: TargetDevice[] = [];
    const pids: number[] = [];
    let targetProcess: TargetProcess | null = null;

    program
        .option("-U, --usb", "Connect to USB device", () => {
            targetDevices.push({
                kind: "usb"
            });
        })
        .option("-R, --remote", "Connect to remote frida-server", () => {
            targetDevices.push({
                kind: "remote"
            });
        })
        .option("-H --host [HOST]", "Connect to remote frida-server by host", (host: string) => {
            targetDevices.push({
                kind: "by-host",
                host: host
            });
        })
        .option("-D, --device [ID]", "Connect to device with the given ID", (id: string) => {
            targetDevices.push({
                kind: "by-id",
                id: id
            });
        })
        .option("-f, --file [FILE]", "Spawn FILE", (file: string) => {
            targetProcess = {
                kind: "spawn",
                program: file
            };
        })
        .option("-n, --attach-name [NAME]", "Attach to NAME", (name: string) => {
            targetProcess = {
                kind: "by-name",
                name: name
            };
        })
        .option("-a, --all-by-name [NAME]", "Attach to all processes named NAME", (name: string) => {
            targetProcess = {
                kind: "all-by-name",
                name: name
            };
        })
        .option("-1, --any-by-name [NAME]", "Attach to any process named NAME", (name: string) => {
            targetProcess = {
                kind: "any-by-name",
                name: name
            };
        })
        .option("-p, --attach-pid [PID]", "Attach to PID", (id: string) => {
            pids.push(parseInt(id, 10));
            targetProcess = {
                kind: "by-ids",
                ids: pids
            };
        })
        .option("-F, --attach-frontmost", "attach to frontmost application", () => {
            targetProcess = {
                kind: "by-frontmost"
            };
        })
        .option("-w, --wait [NAME]", "Attach to NAME as soon as it's spawned", (name: string) => {
            targetProcess = {
                kind: "by-gating",
                name: name
            };
        })
        .parse(process.argv);

    if (process.argv.length < 3) {
        program.help();
    }

    if (targetDevices.length === 0) {
        targetDevices.push({
            kind: "local"
        });
    }

    if (targetProcess === null) {
        targetProcess = inferTargetProcess(program);
    }

    return {
        targetDevices,
        targetProcess
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
