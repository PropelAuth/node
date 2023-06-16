import http from "https"

export type HttpResponse = {
    statusCode?: number
    response: string
}

export function httpRequest(
    authUrlOrigin: URL,
    apiKey: string,
    path: string,
    method: string,
    body?: string
): Promise<HttpResponse> {
    let userAgent = `propelauth-node/${process.env.npm_package_version} node/${process.version} ${process.platform}/${process.arch}`
    let headers: any = {
        Authorization: "Bearer " + apiKey,
        "Content-Type": "application/json",
        "User-Agent": userAgent,
    }
    if (body !== undefined) {
        headers["Content-Length"] = Buffer.byteLength(body)
    }

    return new Promise((resolve, reject) => {
        const req = http.request(
            {
                protocol: authUrlOrigin.protocol,
                hostname: authUrlOrigin.hostname,
                port: authUrlOrigin.port,
                path: path,
                method: method,
                headers: headers,
            },
            (res) => {
                let response = ""
                res.on("data", (data) => {
                    response += data
                })
                res.on("end", () => {
                    resolve({
                        statusCode: res.statusCode,
                        response: response,
                    })
                })
            }
        )

        req.on("error", (error) => {
            reject(error)
        })

        if (body !== undefined) {
            req.write(body)
        }

        req.end()
    })
}
