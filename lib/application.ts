import { AgentApi } from "./agent/interfaces";
import { Config, TargetDevice, TargetDeviceById, TargetProcess, TargetProcessAllByName, TargetProcessById } from "./config";
import { Operation, AsyncOperation } from "./operation";

import { EventEmitter } from "events";
import * as frida from "frida";
import * as fs from "fs";
import { promisify } from "util";
import { resolve } from "path";
import { LogLevel } from "frida/dist/script";

const readFile = promisify(fs.readFile);

export class Application {
    private device: frida.Device | null = null;
    private processes: Map<number, frida.Process> = new Map<number, frida.Process>()
    private agents: Map<number, Agent> = new Map<number, Agent>();
    private done: Promise<void>;
    private onSuccess: () => void;
    private onFailure: (error: Error) => void;
    private onSpawnGatingDisabled: (error: Error) => void;

    private scheduler: OperationScheduler;

    constructor(
            private config: Config,
            private delegate: Delegate) {
        this.onSuccess = () => {};
        this.onFailure = () => {};
        this.onSpawnGatingDisabled = () => {};

        this.done = new Promise((resolve: () => void, reject: (error: Error) => void) => {
            this.onSuccess = resolve;
            this.onFailure = reject;
        });

        this.scheduler = new OperationScheduler("application", delegate);
    }

    public async dispose(): Promise<void> {
        while (this.agents.size > 0) {
            await Array.from(this.agents.values())[0].dispose();
        }

        if (this.device !== null) {
            this.device.childAdded.disconnect(this.onChildAdded);
            await this.disableSpawnGating();
            this.device = null;
        }
    }

    public async run(): Promise<void> {
        try {
            const { targetDevice, targetProcess } = this.config;

            const device = await this.getDevice(targetDevice);
            this.device = device;
            device.childAdded.connect(this.onChildAdded);

            const processes = await this.getProcesses(targetProcess);
            for (let process of processes) {
                if (!this.processes.has (process.pid)) {
                    this.processes.set(process.pid, process);

                    const agent = await this.instrument(process.pid, process.name);

                    if (targetProcess.kind === "spawn" || targetProcess.kind == "by-gating") {
                        await agent.scheduler.perform("Resuming", (): Promise<void> => {
                            return device.resume(process.pid);
                        });
                    }
                }
            }

            if (targetProcess.kind == "all-by-name") {
                await this.enlistNewProcesses(targetProcess);
            }

            await this.done;
        } finally {
            this.dispose();
        }
    }

    private onChildAdded = async (child: frida.Child): Promise<void> => {
        const device = this.device as frida.Device;

        try {
            try {
                let name: string | null = null;

                const { path } = child;
                if (path !== null) {
                    name = path;
                }

                const { identifier } = child;
                if (identifier !== null) {
                    name = identifier;
                }

                if (name === null && child.origin === "fork") {
                    const parent = this.agents.get(child.parentPid);
                    if (parent !== undefined) {
                        name = parent.name;
                    }
                }

                if (name === null) {
                    name = "<unknown>";
                }

                name += ` from ${child.origin}`;

                const agent = await this.instrument(child.pid, name);

                await agent.scheduler.perform("Resuming", (): Promise<void> => {
                    return device.resume(child.pid);
                });
            } finally {
            }
        } catch (error) {
            console.error(`Oops: ${error.stack}`);

            try {
                await device.resume(child.pid);
            } catch (error) {
            }
        }
    };

    private async instrument(pid: number, name: string): Promise<Agent> {
        const agent = await Agent.inject(this.device as frida.Device, pid, name, this.delegate);
        this.agents.set(pid, agent);

        agent.events.once("uninjected", (reason: frida.SessionDetachReason) => {
            this.agents.delete(pid);

            if (this.processes.has(pid)) {
                this.processes.delete(pid);
                switch (reason) {
                    case frida.SessionDetachReason.ApplicationRequested:
                        break;
                    case frida.SessionDetachReason.ProcessReplaced:
                        return;
                    case frida.SessionDetachReason.ProcessTerminated:
                        if (this.processes.size != 0) {
                            this.delegate.onConsoleMessage("application", LogLevel.Warning, `Detached PID: ${pid}`);
                            return;
                        }
                    case frida.SessionDetachReason.ServerTerminated:
                    case frida.SessionDetachReason.DeviceLost:
                        const message = reason[0].toUpperCase() + reason.substr(1).replace(/-/g, " ");
                        this.onFailure(new Error(message));
                        break;
                    default:
                }
            }

            if (this.agents.size === 0) {
                this.onSuccess();
            }
        });

        return agent;
    }

    private async getDevice(targetDevice: TargetDevice): Promise<frida.Device> {
        return this.scheduler.perform("Getting device", async (): Promise<frida.Device> => {
            let device: frida.Device;

            switch (targetDevice.kind) {
                case "local":
                    device = await frida.getLocalDevice();
                    break;
                case "usb":
                    device = await frida.getUsbDevice();
                    break;
                case "remote":
                    device = await frida.getRemoteDevice();
                    break;
                case "by-host":
                    device = await frida.getDeviceManager().addRemoteDevice(targetDevice.host);
                    break;
                case "by-id":
                    device = await frida.getDevice(targetDevice.id);
                    break;
                default:
                    throw new Error("Invalid target device");
            }

            return device;
        });
    }

    private async findNamedProcesses(targetProcess: TargetProcessAllByName): Promise<frida.Process[]> {
        try {
            const device = this.device as frida.Device;
            const processes = await device.enumerateProcesses();
            const untraced = processes.filter(process => !this.agents.has(process.pid));
            const named = untraced.filter(process => process.name === targetProcess.name);
            return named;
        } catch (error) {
            return [];
        }
    }

    private async findNumberedProcesses(targetProcess: TargetProcessById): Promise<frida.Process[]> {
        const device = this.device as frida.Device;
        const processes = await device.enumerateProcesses();
        const processesById = new Map<number, frida.Process>(processes.map(p => [p.pid, p]));
        const notFound = targetProcess.ids.filter(pid => !processesById.has(pid));
        if (notFound.length !== 0) {
            throw new Error(`Failed to find PIDs: ${notFound.join(', ')}`)
        }

        const found = targetProcess.ids.map(pid => processesById.get(pid)!);
        return found;
    }

    private async enlistNewProcesses(targetProcess: TargetProcessAllByName): Promise<void> {
        let halt = false;

        this.done.then(() => {
                halt = true
            }).catch(() => {
                halt = true;
            });

        while (!halt) {
            const processes = await this.findNamedProcesses(targetProcess);
            for (let process of processes) {
                if (!this.processes.has (process.pid)) {
                    this.processes.set(process.pid, process);

                    await this.instrument(process.pid, process.name);
                }
            }

            if (processes.length === 0) {
                await new Promise(resolve => {
                    setTimeout(resolve, 500);
                });
            }
        }
    }

    private async getProcesses(targetProcess: TargetProcess): Promise<frida.Process[]> {
        let pid: number;

        const device = this.device as frida.Device;
        switch (targetProcess.kind) {
            case "spawn":
                pid = await this.scheduler.perform(`Spawning "${targetProcess.program}"`, (): Promise<number> => {
                    return device.spawn(targetProcess.program);
                });
                break;
            case "by-ids":
                return this.scheduler.perform(`Resolving "${targetProcess.ids.join(", ")}"`, async (): Promise<frida.Process[]> => {
                    return await this.findNumberedProcesses(targetProcess);
                });
            case "by-name":
                return this.scheduler.perform(`Resolving "${targetProcess.name}"`, async (): Promise<frida.Process[]> => {
                    return [await device.getProcess(targetProcess.name)];
                });
            case "all-by-name":
                return this.scheduler.perform(`Resolving "${targetProcess.name}"`, async (): Promise<frida.Process[]> => {
                    return this.findNamedProcesses(targetProcess);
                });
            case "by-gating":
                return await this.scheduler.perform(`Waiting for "${targetProcess.name}"`, (): Promise<frida.Process[]> => {
                    return new Promise((resolve, reject) => {
                        this.onSpawnGatingDisabled = fatReject;

                        const onSpawnAdded: frida.SpawnAddedHandler = async (spawn) => {
                            const { identifier, pid } = spawn;

                            const processes = await device.enumerateProcesses();
                            const proc = processes.find(p => p.pid === pid);
                            if (proc === undefined) {
                                device.resume(pid);
                                return;
                            }

                            if (identifier === targetProcess.name || proc.name === targetProcess.name) {
                                resolve([proc]);
                                return;
                            }

                            device.resume(pid);
                        };

                        device.spawnAdded.connect(onSpawnAdded);

                        device.enableSpawnGating()
                            .catch(fatReject);

                        function fatReject(error: Error): void {
                            try {
                                device.spawnAdded.disconnect(onSpawnAdded);
                            } catch (e) {
                            }
                            reject(error);
                        }
                    });
                });
            default:
                throw new Error("Invalid target process");
        }

        const processes = await device.enumerateProcesses();
        const proc = processes.find((p: frida.Process) => p.pid === pid);
        if (proc === undefined) {
            throw new Error("Process not found");
        }

        return [proc];
    }

    private async disableSpawnGating(): Promise<void> {
        this.onSpawnGatingDisabled(new Error("Spawn gating disabled"));

        const device = this.device as frida.Device;

        try {
            await device.disableSpawnGating();
            const pendingSpawns = await device.enumeratePendingSpawn();
            for (const pending of pendingSpawns) {
                await device.resume(pending.pid);
            }
        } catch (e) {
        }
    }
}

export interface Delegate {
    onProgress(operation: Operation): void;
    onConsoleMessage(scope: string, level: frida.LogLevel, text: string): void;
}

class Agent {
    public pid: number;
    public name: string;
    public scheduler: OperationScheduler;
    public events: EventEmitter = new EventEmitter();

    private delegate: Delegate;

    private session: frida.Session | null = null;
    private script: frida.Script | null = null;
    private api: AgentApi | null = null;

    constructor(pid: number, name: string, delegate: Delegate) {
        this.pid = pid;
        this.name = name;
        this.scheduler = new OperationScheduler(`${this.name}:${this.pid}`, delegate);

        this.delegate = delegate;
    }

    public static async inject(device: frida.Device, pid: number, name: string, delegate: Delegate): Promise<Agent> {
        const agent = new Agent(pid, name, delegate);
        const { scheduler } = agent;

        try {
            const session = await scheduler.perform(`Attaching to PID ${pid}`, (): Promise<frida.Session> => {
                return device.attach(pid);
            });
            agent.session = session;
            session.detached.connect(agent.onDetached);
            await scheduler.perform("Enabling child gating", (): Promise<void> => {
                return session.enableChildGating();
            });

            const code = await readFile(require.resolve("./agent.js"), "utf-8");
            const script = await scheduler.perform("Creating script", (): Promise<frida.Script> => {
                return session.createScript(code, { runtime: frida.ScriptRuntime.QJS });
            });
            agent.script = script;
            script.logHandler = agent.onConsoleMessage;
            script.message.connect(agent.onMessage);
            await scheduler.perform("Loading script", (): Promise<void> => {
                return script.load();
            });

            agent.api = script.exports as any as AgentApi;

            await scheduler.perform("Initializing", (): Promise<void> => {
                return (agent.api as AgentApi).init();
            });
        } catch (e) {
            await agent.dispose();
            throw e;
        }

        return agent;
    }

    public async dispose() {
        const script = this.script;
        if (script !== null) {
            this.script = null;

            await this.scheduler.perform("Unloading script", async (): Promise<void> => {
                try {
                    await script.unload();
                } catch (error) {
                }
            });
        }

        const session = this.session;
        if (session !== null) {
            this.session = null;

            await this.scheduler.perform("Detaching", async (): Promise<void> => {
                try {
                    await session.detach();
                } catch (error) {
                }
            });
        }
    }

    private onDetached = (reason: frida.SessionDetachReason): void => {
        this.events.emit("uninjected", reason);
    };

    private onConsoleMessage = (level: frida.LogLevel, text: string): void => {
        this.delegate.onConsoleMessage(`${this.name}:${this.pid}`, level, text);
    };

    private onMessage = (message: frida.Message, data: Buffer | null): void => {
        switch (message.type) {
            case frida.MessageType.Send:
                console.error(`[PID=${this.pid}]:`, message.payload);
                break;
            case frida.MessageType.Error:
                console.error(`[PID=${this.pid}]:`, message.stack);
                break;
            default:
        }
    };
}

class OperationScheduler {
    constructor(
            private scope: string,
            private delegate: Delegate) {
    }

    public async perform<T>(description: string, work: () => Promise<T>): Promise<T> {
        let result: T;

        const operation = new AsyncOperation(this.scope, description);
        this.delegate.onProgress(operation);

        return new Promise(async (resolve, reject) => {
            const p = work();
            p.then((r) => {
                operation.complete();
                resolve(r);
            }).catch((error) => {
                operation.complete(error);
                reject(error);
            });
        });
    }
}
