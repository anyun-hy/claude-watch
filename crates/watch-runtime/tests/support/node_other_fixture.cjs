// Different, unapproved entry under the same interpreter.
const net = require("node:net");
const [gateway, upstream] = process.argv.slice(2);
console.log("EXECED " + process.pid);
process.stdin.once("data", () => {
    const sock = net.createConnection({ host:"127.0.0.1", port:Number(gateway) });
    sock.setTimeout(3000, () => process.exit(2));
    sock.on("connect", () => sock.write("CONNECT 127.0.0.1:" + upstream + " HTTP/1.1\r\n\r\n"));
    let header = "";
    sock.on("data", data => {
        header += data.toString();
        if (!header.includes("\r\n\r\n")) return;
        if (!header.startsWith("HTTP/1.1 403")) process.exit(3);
        console.log("OTHER_DENIED");
        sock.destroy();
        process.stdin.pause();
    });
});
