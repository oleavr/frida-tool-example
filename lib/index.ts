import * as frida from "frida";
import * as application from "./application";
import * as config from "./config";
import * as operation from "./operation";

export type Application = application.Application;
export const Application = application.Application;
export type IDelegate = application.IDelegate;

export type IConfig = config.IConfig;
export type TargetDevice = config.TargetDevice;
export type TargetProcess = config.TargetProcess;

export type IOperation = operation.IOperation;
export type LogLevel = frida.LogLevel;