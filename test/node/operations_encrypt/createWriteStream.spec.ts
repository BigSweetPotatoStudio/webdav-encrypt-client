import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import { PassThrough } from "stream";
import waitOn from "wait-on";
import { expect } from "chai";
import {
    SERVER_PASSWORD,
    SERVER_PORT,
    SERVER_USERNAME,
    clean,
    createWebDAVClient,
    createWebDAVServer,
    restoreRequests,
    useRequestSpy
} from "../../helpers.node.s.js";

const dirname = path.dirname(fileURLToPath(import.meta.url));

const TEST_CONTENTS = path.resolve(dirname, "../../testContents");
const IMAGE_SOURCE = path.join(TEST_CONTENTS, "./alrighty.jpg");
const TEXT_SOURCE = path.join(TEST_CONTENTS, "./notes.txt");

function waitOnFile(filename: string) {
    return new Promise<void>(function (resolve, reject) {
        waitOn(
            {
                resources: [filename],
                interval: 50,
                timeout: 500,
                window: 0
            },
            function (err: Error) {
                if (err) {
                    return reject(err);
                }
                return resolve();
            }
        );
    });
}

describe("createWriteStream", function () {
    beforeEach(function () {
        this.client = createWebDAVClient(`http://localhost:${SERVER_PORT}/webdav/server`, {
            username: SERVER_USERNAME,
            password: SERVER_PASSWORD
        });
        clean();
        this.server = createWebDAVServer();
        this.requestSpy = useRequestSpy();
        return this.server.start();
    });

    afterEach(async function () {
        restoreRequests();
        await new Promise(resolve => {
            setTimeout(resolve, 500);
        });
        return this.server.stop();
    });

    it("writes the file to the remote", function () {
        const targetFile = path.join(TEST_CONTENTS, "./alrighty2.jpg");
        const writeStream = this.client.createWriteStream("/alrighty2.jpg");
        const readStream = fs.createReadStream(IMAGE_SOURCE);
        expect(writeStream instanceof PassThrough).to.be.true;
        return new Promise(function (resolve, reject) {
            writeStream.on("end", function () {
                // stupid stream needs time to close probably..
                waitOnFile(targetFile).then(resolve, reject);
            });
            writeStream.on("error", reject);
            readStream.pipe(writeStream);
        });
    });

    it("allows specifying custom headers", async function () {
        const writeStream = this.client.createWriteStream("/alrighty2.jpg", {
            headers: {
                "X-test": "test"
            }
        });
        fs.createReadStream(TEXT_SOURCE).pipe(writeStream);
        const [, requestOptions] = this.requestSpy.firstCall.args;
        expect(requestOptions).to.have.property("headers").that.has.property("X-test", "test");
    });

    it("calls the callback function with the response", function (done) {
        const readStream = fs.createReadStream(TEXT_SOURCE);
        const writeStream = this.client.createWriteStream(
            "/test.txt",
            undefined,
            (response: Response) => {
                expect(response).to.have.property("status", 201);
                done();
            }
        );
        readStream.pipe(writeStream);
    });
});
