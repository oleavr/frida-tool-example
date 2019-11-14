export interface IConfig {
    targetDevice: TargetDevice;
    targetProcess: TargetProcess;
}

export type TargetDevice = ITargetDeviceLocal | ITargetDeviceUsb | ITargetDeviceRemote | ITargetDeviceByHost | ITargetDeviceById;
export type TargetProcess = ITargetProcessSpawn | ITargetProcessByName | ITargetProcessById | ITargetProcessByGating;

export interface ITargetDeviceLocal {
    kind: "local";
}

export interface ITargetDeviceUsb {
    kind: "usb";
}

export interface ITargetDeviceRemote {
    kind: "remote";
}

export interface ITargetDeviceByHost {
    kind: "by-host";
    host: string;
}

export interface ITargetDeviceById {
    kind: "by-id";
    id: string;
}

export interface ITargetProcessSpawn {
    kind: "spawn";
    program: string;
}

export interface ITargetProcessByName {
    kind: "by-name";
    name: string;
}

export interface ITargetProcessById {
    kind: "by-id";
    id: number;
}

export interface ITargetProcessByGating {
    kind: "by-gating";
    name: string;
}
