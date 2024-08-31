import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import bufferEquals from "buffer-equals";
import { expect } from "chai";
import {
    SERVER_PASSWORD,
    SERVER_PORT,
    SERVER_USERNAME,
    clean,
    createWebDAVClient,
    createWebDAVServer,
    sleep
} from "../../helpers.node.s.js";

const dirname = path.dirname(fileURLToPath(import.meta.url));

const SOURCE_BIN = path.resolve(dirname, "../../testContents/alrighty.jpg");
const TARGET_BIN = path.resolve(dirname, "../../testContents/sub1/alrighty.jpg");
const TARGET_TXT = path.resolve(dirname, "../../testContents/newFile.txt");
const TARGET_TXT_CHARS = path.resolve(dirname, "../../testContents/จะทำลาย.txt");

async function main() {
    let client = createWebDAVClient(`http://localhost:${SERVER_PORT}/webdav/server/`, {
        username: SERVER_USERNAME,
        password: SERVER_PASSWORD,
        encrypt: true,
        secretKey: "123456"
    });
    clean();
    let server = createWebDAVServer();
    await server.start();
    if (!(await client.exists("/sub1"))) {
        await client.createDirectory("/sub1");
    }
    const imgBin = fs.readFileSync(SOURCE_BIN);
    await client.putFileContents("/sub1/alrighty.jpg", imgBin);
    let written = await client.getFileContents("/sub1/alrighty.jpg");
    expect(bufferEquals(written, imgBin)).to.be.true;

    // const text = "this is\nsome text\ncontent\t...\n";
    // await client.putFileContents("/sub1/newFile.txt", text);
    // let text2 = await client.getFileContents("/sub1/newFile.txt", { format: "text" });
    // expect(text2).to.equal(text);

    // const imgBin = fs.readFileSync(SOURCE_BIN);
    // await client.putFileContents("/sub1/alrighty2.jpg", fs.createReadStream(SOURCE_BIN));
    // let written = await client.getFileContents("/sub1/alrighty2.jpg", { format: "binary" });
    // expect(bufferEquals(written, imgBin)).to.be.true;

    // const imgBin = fs.readFileSync(SOURCE_BIN);
    // await client.putFileContents("/sub1/alrighty2.jpg", fs.createReadStream(SOURCE_BIN));

    // await client
    //     .createReadStream("/sub1/alrighty2.jpg")
    //     .pipe(fs.createWriteStream(path.resolve(dirname, "../../testContents/alrighty2.jpg")));
    // // await new Promise(resolve => setTimeout(resolve, 1000));
    // await sleep(3000);
    // const imgBin2 = fs.readFileSync(path.resolve(dirname, "../../testContents/alrighty2.jpg"));
    // expect(bufferEquals(imgBin2, imgBin)).to.be.true;

    // let written = await client.getFileContents("/sub1/alrighty2.jpg", { format: "binary" });

    // expect(bufferEquals(written, imgBin)).to.be.true;

    await server.stop();
}

main();
