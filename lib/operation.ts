import { EventEmitter } from "events";

export type HRTime = any;

export interface Operation {
    scope: string;
    description: string;
    elapsed: HRTime;
    onceComplete(callback: (error?: Error) => void): void;
}

export class AsyncOperation implements Operation {
    get elapsed(): HRTime {
        if (this.#duration === null) {
            return process.hrtime(this.#startTime);
        }

        return this.#duration;
    }

    #startTime: HRTime = process.hrtime();
    #duration: HRTime | null = null;
    #events: EventEmitter = new EventEmitter();

    constructor(
            public scope: string,
            public description: string) {
    }

    public onceComplete(callback: (error?: Error) => void) {
        this.#events.once("complete", callback);
    }

    public complete(error?: Error) {
        this.#duration = process.hrtime(this.#startTime);
        this.#events.emit("complete", error);
    }
}
