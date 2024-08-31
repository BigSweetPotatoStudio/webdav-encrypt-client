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

describe("put and get", function () {
    beforeEach(function () {
        this.client = createWebDAVClient(`http://localhost:${SERVER_PORT}/webdav/server`, {
            username: SERVER_USERNAME,
            password: SERVER_PASSWORD,
            encrypt: true,
            secretKey: "123456"
        });
        clean();
        this.server = createWebDAVServer();
        return this.server.start();
    });

    afterEach(function () {
        return this.server.stop();
    });

    it("test buffer", async function () {
        if (!(await this.client.exists("/sub1"))) {
            await this.client.createDirectory("/sub1");
        }
        const imgBin = fs.readFileSync(SOURCE_BIN);
        await this.client.putFileContents("/sub1/test.jpg", imgBin);
        let written = await this.client.getFileContents("/sub1/test.jpg");
        expect(bufferEquals(written, imgBin)).to.be.true;
    });

    it("test text", async function () {
        if (!(await this.client.exists("/sub1"))) {
            await this.client.createDirectory("/sub1");
        }
        const text = "this is\nsome text\ncontent\t...\n";
        await this.client.putFileContents("/sub1/newFile.txt", text);
        let text2 = await this.client.getFileContents("/sub1/newFile.txt", { format: "text" });
        expect(text2).to.equal(text);
    });

    it("test Stream", async function () {
        if (!(await this.client.exists("/sub1"))) {
            await this.client.createDirectory("/sub1");
        }
        const imgBin = fs.readFileSync(SOURCE_BIN);
        await this.client.putFileContents("/sub1/alrighty2.jpg", fs.createReadStream(SOURCE_BIN));

        await this.client
            .createReadStream("/sub1/alrighty2.jpg")
            .pipe(fs.createWriteStream(path.resolve(dirname, "../../testContents/alrighty2.jpg")));
        // await new Promise(resolve => setTimeout(resolve, 1000));
        await sleep(3000);
        const imgBin2 = fs.readFileSync(path.resolve(dirname, "../../testContents/alrighty2.jpg"));
        expect(bufferEquals(imgBin2, imgBin)).to.be.true;
    });
});
