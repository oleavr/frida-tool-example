export interface Config {
    targetDevice: TargetDevice;
    targetProcess: TargetProcess;
}

export type TargetDevice =
    | TargetDeviceLocal
    | TargetDeviceUsb
    | TargetDeviceRemote
    | TargetDeviceByHost
    | TargetDeviceById
    ;

export type TargetProcess =
    | TargetProcessSpawn
    | TargetProcessByName
    | TargetProcessAllByName
    | TargetProcessById
    | TargetProcessByGating
    ;

export interface TargetDeviceLocal {
    kind: "local";
}

export interface TargetDeviceUsb {
    kind: "usb";
}

export interface TargetDeviceRemote {
    kind: "remote";
}

export interface TargetDeviceByHost {
    kind: "by-host";
    host: string;
}

export interface TargetDeviceById {
    kind: "by-id";
    id: string;
}

export interface TargetProcessSpawn {
    kind: "spawn";
    program: string;
}

export interface TargetProcessByName {
    kind: "by-name";
    name: string;
}

export interface TargetProcessAllByName {
    kind: "all-by-name";
    name: string;
}

export interface TargetProcessById {
    kind: "by-ids";
    ids: number[];
}

export interface TargetProcessByGating {
    kind: "by-gating";
    name: string;
}
