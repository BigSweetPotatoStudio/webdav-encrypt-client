import { expect } from "chai";
import { AuthType } from "../../../source/encrypt";
import { createWebDAVClient } from "../../helpers.node.s.js";

describe("getFileDownloadLink", function () {
    beforeEach(function () {
        this.clientPub = createWebDAVClient("http://test.com");
        this.clientAuth = createWebDAVClient("https://test.com", {
            username: "user",
            password: "pass"
        });
    });

    it("generates authenticated links", function () {
        const link = this.clientAuth.getFileDownloadLink("/test/file.txt");
        expect(link).to.equal("https://user:pass@test.com/test/file.txt");
    });

    it("generates unauthenticated links", function () {
        const link = this.clientPub.getFileDownloadLink("/test/file.txt");
        expect(link).to.equal("http://test.com/test/file.txt");
    });

    it("throws for digest authentication", function () {
        this.client = createWebDAVClient("https://test.com", {
            username: "user",
            password: "pass",
            authType: AuthType.Digest
        });
        expect(() => {
            this.client.getFileDownloadLink("/test/file.txt");
        }).to.throw(/Unsupported auth type.+digest/i);
    });
});
