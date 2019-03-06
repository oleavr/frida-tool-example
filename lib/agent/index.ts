import { IAgent } from "./interfaces";

class Agent implements IAgent {
    public async init(): Promise<void> {
        console.log(`Hello World from PID: ${Process.id}`);
        console.warn("Example warning");
        console.error("Example error");
    }
}

const agent = new Agent();
rpc.exports = Object.getPrototypeOf(agent);