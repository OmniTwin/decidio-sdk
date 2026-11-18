declare module "@langchain/langgraph" {
  export function interrupt(value: unknown): unknown;
  export class Command {
    constructor(arg: { resume?: unknown; [k: string]: unknown });
  }
}

declare module "@temporalio/workflow" {
  export interface SignalDefinition<Args extends unknown[] = unknown[]> {
    readonly name: string;
    readonly _args?: Args;
  }
  export function defineSignal<Args extends unknown[] = []>(name: string): SignalDefinition<Args>;
  export function setHandler(def: SignalDefinition<any>, handler: (...args: any[]) => void): void;
  export function condition(fn: () => boolean, timeout?: number | string): Promise<boolean | void>;
  export function uuid4(): string;
}
