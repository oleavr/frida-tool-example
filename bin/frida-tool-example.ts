import {
    Application,
    Config,
    Delegate,
    Operation,
    LogLevel,
    TargetDevice,
    TargetProcess,
} from "../lib";

import chalk, { Chalk } from "chalk";
import program from "commander";
import prettyHrtime from "pretty-hrtime";

async function main(): Promise<void> {
    try {
        const config = parseArguments();
        const ui = new ConsoleUI();

        let app: Application | null = new Application(config, ui);

        process.on("SIGINT", stop);
        process.on("SIGTERM", stop);

        await app.run();

        function stop(): void {
            if (app !== null) {
                app.dispose();
                app = null;
            }
        }
    } catch (error) {
        process.exitCode = 1;
        process.stderr.write(`${chalk.redBright(error.message)}\n`);
    }
}

class ConsoleUI implements Delegate {
    private pendingOperation: PendingOperation | null = null;

    public onProgress(operation: Operation): void {
        process.stdout.write(`[${operation.scope}] ${chalk.cyan(operation.description)} `);

        const pending = {
            operation: operation,
            logMessageCount: 0,
        };
        this.pendingOperation = pending;

        operation.onceComplete(() => {
            if (pending.logMessageCount > 0) {
                process.stdout.write(`[${operation.scope}] ${chalk.cyan(`${operation.description} completed`)} `);
            }

            process.stdout.write(chalk.gray(`(${prettyHrtime(operation.elapsed)})\n`));

            this.pendingOperation = null;
        });
    }

    public onConsoleMessage(scope: string, level: LogLevel, text: string): void {
        let c: Chalk;
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

function parseArguments(): Config {
    let targetDevice: TargetDevice = {
        kind: "local"
    };
    let pids: number[] = [];
    let targetProcess: TargetProcess | null = null;

    program
        .option("-U, --usb", "Connect to USB device", () => {
            targetDevice = {
                kind: "usb"
            };
        })
        .option("-R, --remote", "Connect to remote frida-server", () => {
            targetDevice = {
                kind: "remote"
            };
        })
        .option("-H --host [HOST]", "Connect to remote frida-server by host", (host: string) => {
            targetDevice = {
                kind: "by-host",
                host: host
            };
        })
        .option("-D, --device [ID]", "Connect to device with the given ID", (id: string) => {
            targetDevice = {
                kind: "by-id",
                id: id
            };
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
        .option("-p, --attach-pid [PID]", "Attach to PID", (id: string) => {
            pids.push(parseInt(id, 10));
            targetProcess = {
                kind: "by-ids",
                ids: pids
            };
        })
        .option("-w, --wait [NAME]", "Attach to NAME as soon as it's spawned", (name: string) => {
            targetProcess = {
                kind: "by-gating",
                name: name
            };
        })
        .parse(process.argv);

    if (targetProcess === null) {
        targetProcess = inferTargetProcess(program);
    }

    return {
        targetDevice,
        targetProcess
    };
}

function inferTargetProcess(prog: program.CommanderStatic): TargetProcess {
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
