import { joinURL } from "../tools/url.js";
import { encodePath } from "../tools/path.js";
import { request, prepareRequestOptions } from "../request.js";
import { handleResponseCode } from "../response.js";
import {
    WebDAVMethodOptions,
    WebDAVClientContext,
    WebDAVClientError,
    DavCompliance
} from "../types.js";

export async function getDavCompliance(
    context: WebDAVClientContext,
    filePath: string,
    options: WebDAVMethodOptions = {}
): Promise<DavCompliance> {
    const requestOptions = prepareRequestOptions(
        {
            url: joinURL(context.remoteURL, encodePath(filePath)),
            method: "OPTIONS"
        },
        context,
        options
    );
    const response = await request(requestOptions);
    try {
        handleResponseCode(context, response);
    } catch (err) {
        const error = err as WebDAVClientError;
        throw error;
    }
    const davHeader = response.headers.get("DAV") ?? "";
    const compliance = davHeader.split(",").map(item => item.trim());
    const server = response.headers.get("Server") ?? "";
    return {
        compliance,
        server
    };
}
