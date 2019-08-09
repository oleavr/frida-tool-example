export interface IConfig {
    targetDevice: TargetDevice;
    targetProcess: TargetProcess;
}

export type TargetDevice = ITargetDeviceLocal | ITargetDeviceUsb | ITargetDeviceRemote | ITargetDeviceById | ITargetDeviceByHost;
export type TargetProcess = ITargetProcessSpawn | ITargetProcessByName | ITargetProcessById | ITargetProcessByHost;

export interface ITargetDeviceLocal {
    kind: "local";
}

export interface ITargetDeviceUsb {
    kind: "usb";
}

export interface ITargetDeviceRemote {
    kind: "remote";
}

export interface ITargetDeviceById {
    kind: "by-id";
    id: string;
}

export interface ITargetDeviceByHost {
    kind: "by-host";
    host: string;
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

export interface ITargetProcessByHost {
    kind: "by-host";
    host: string;
}