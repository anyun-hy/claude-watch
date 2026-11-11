#!/usr/bin/env node
// Owned npm-shaped ESM fixture. No real CLI or external addresses.
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import net from "node:net";
import readline from "node:readline";
import { once } from "node:events";
import { relativeFixture } from "./relative.js";
const [gateway, upstream, input, output, addon, different] = process.argv.slice(2);
const sockets = [];
async function connect() {
    const client = net.createConnection({ host:"127.0.0.1", port:Number(gateway) });
    client.setTimeout(3000, () => client.destroy(new Error("fixture socket timeout")));
    await once(client, "connect");
    client.write("CONNECT 127.0.0.1:" + upstream + " HTTP/1.1\r\nHost: 127.0.0.1:" + upstream + "\r\n\r\n");
    let buffered = Buffer.alloc(0);
    async function take(length) {
        let count;
        while ((count = length(buffered)) < 0) {
            const bytes = client.read();
            if (bytes) buffered = Buffer.concat([buffered, bytes]);
            else {
                if (client.readableEnded) throw new Error("unexpected EOF");
                await once(client, "readable");
            }
        }
        const value = buffered.subarray(0, count);
        buffered = buffered.subarray(count);
        return value.toString();
    }
    const header = await take(bytes => {
        const end = bytes.indexOf("\r\n\r\n");
        return end < 0 ? -1 : end + 4;
    });
    client.setTimeout(0);
    async function eof() {
        if (buffered.length || client.read()?.length) throw new Error("unexpected bytes before EOF");
        if (client.readableEnded) return;
        await new Promise((resolve, reject) => {
            client.once("end", resolve);
            client.once("error", reject);
            client.once("data", () => reject(new Error("unexpected data during cutoff")));
            client.resume();
        });
    }
    return { client, header, take, eof };
}
let differentChild;
console.log("READY " + process.pid + " " + JSON.stringify({
    marker:relativeFixture, path:process.argv[1], cwd:process.cwd(), main:import.meta.main,
    execPath:process.execPath, startupOption:Object.hasOwn(process.env,"NODE_OPTIONS"),
    argv:process.argv.slice(8)
}));
for await (const line of readline.createInterface({ input:process.stdin })) {
    if (line === "OPEN") {
        const s = await connect();
        if (!s.header.startsWith("HTTP/1.1 200")) throw new Error(s.header);
        s.client.write("echo-script");
        const echo = await s.take(bytes => bytes.length >= 11 ? 11 : -1);
        if (echo !== "echo-script") throw new Error("bad echo");
        sockets.push(s);
        console.log("OPENED");
    } else if (line === "EOF") {
        for (const s of sockets) { await s.eof(); s.client.destroy(); }
        console.log("EOF " + sockets.splice(0).length);
    } else if (line === "RECONNECT 403") {
        const s = await connect();
        if (!s.header.startsWith("HTTP/1.1 403")) throw new Error(s.header);
        s.client.destroy();
        console.log("DENIED");
    } else if (line.startsWith("PING ")) {
        console.log("PONG " + process.pid + " " + line.slice(5));
    } else if (line === "FORK") {
        const api = createRequire(import.meta.url)(addon);
        console.log("FORKED " + api.forkChild(input, output, Number(gateway), Number(upstream)));
    } else if (line === "EXEC_OTHER") {
        differentChild = spawn(process.execPath, [different,gateway,upstream], { stdio:["pipe","pipe","inherit"] });
        const [data] = await once(differentChild.stdout, "data");
        console.log(data.toString().trim());
    } else if (line === "OTHER_DENIED") {
        differentChild.stdin.write("check\n");
        const [data] = await once(differentChild.stdout, "data");
        console.log(data.toString().trim());
        differentChild.stdin.end();
    } else if (line === "QUIT") {
        process.exit(23);
    } else {
        throw new Error("unknown fixture command");
    }
}
