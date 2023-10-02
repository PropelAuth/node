import { httpRequest } from "../http"

export type TokenVerificationMetadata = {
    verifierKey: string
    issuer: string
}

const ENDPOINT_PATH = "/api/v1/token_verification_metadata"

// GET
export function fetchTokenVerificationMetadata(
    authUrl: URL,
    integrationApiKey: string,
    manualTokenVerificationMetadata?: TokenVerificationMetadata
): Promise<TokenVerificationMetadata> {
    if (manualTokenVerificationMetadata) {
        return Promise.resolve(manualTokenVerificationMetadata)
    }

    return httpRequest(authUrl, integrationApiKey, ENDPOINT_PATH, "GET").then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when fetching token verification metadata")
        }

        const jsonParse = JSON.parse(httpResponse.response)
        return {
            verifierKey: jsonParse.verifier_key_pem,
            issuer: formatIssuer(authUrl),
        }
    })
}

function formatIssuer(authUrl: URL): string {
    return authUrl.origin
}
