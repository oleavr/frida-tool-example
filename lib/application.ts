import { AgentApi } from "./agent/interfaces";
import { Config, TargetDevice, TargetProcess } from "./config";
import { Operation, AsyncOperation } from "./operation";

import { EventEmitter } from "events";
import * as frida from "frida";
import * as fs from "fs";
import { promisify } from "util";

const readFile = promisify(fs.readFile);

export class Application {
    private device: frida.Device | null = null;
    private process: frida.Process | null = null;
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

            const process = await this.getProcess(targetProcess);
            this.process = process;

            const agent = await this.instrument(process.pid, process.name);

            if (targetProcess.kind === "spawn" || targetProcess.kind == "by-gating") {
                await agent.scheduler.perform("Resuming", (): Promise<void> => {
                    return device.resume(process.pid);
                });
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

            const mainPid = (this.process as frida.Process).pid;
            if (pid === mainPid) {
                switch (reason) {
                    case frida.SessionDetachReason.ApplicationRequested:
                        break;
                    case frida.SessionDetachReason.ProcessReplaced:
                        return;
                    case frida.SessionDetachReason.ProcessTerminated:
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

    private async getProcess(targetProcess: TargetProcess): Promise<frida.Process> {
        let pid: number;

        const device = this.device as frida.Device;
        switch (targetProcess.kind) {
            case "spawn":
                pid = await this.scheduler.perform(`Spawning "${targetProcess.program}"`, (): Promise<number> => {
                    return device.spawn(targetProcess.program);
                });
                break;
            case "by-id":
                pid = targetProcess.id;
                break;
            case "by-name":
                return this.scheduler.perform(`Resolving "${targetProcess.name}"`, (): Promise<frida.Process> => {
                    return device.getProcess(targetProcess.name);
                });
            case "by-gating":
                return await this.scheduler.perform(`Waiting for "${targetProcess.name}"`, (): Promise<frida.Process> => {
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
                                resolve(proc);
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

        return proc;
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
        this.scheduler = new OperationScheduler(name, delegate);

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

            const source = await readFile(require.resolve("./agent"), "utf-8");
            const script = await scheduler.perform("Creating script", (): Promise<frida.Script> => {
                return session.createScript(source);
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
        this.delegate.onConsoleMessage(this.name, level, text);
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

        try {
            result = await work();

            operation.complete();
        } catch (error) {
            operation.complete(error);
            throw error;
        }

        return result;
    }
}
