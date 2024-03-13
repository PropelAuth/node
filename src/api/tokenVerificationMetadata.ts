import * as jose from "jose"
import { UnexpectedException } from "../exceptions"
import { httpRequest } from "../http"

export type TokenVerificationMetadata = {
    verifierKey: string
    issuer: string
}

export interface TokenVerificationMetadataWithPublicKey {
    tokenVerificationMetadata: TokenVerificationMetadata
    publicKey: jose.KeyLike
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
            console.error("Your API key is incorrect")
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            console.error(`Error fetching token verification metadata: ${httpResponse.statusCode}`)
            throw new Error("Unknown error when fetching token verification metadata")
        }

        const jsonParse = JSON.parse(httpResponse.response)
        return {
            verifierKey: jsonParse.verifier_key_pem,
            issuer: formatIssuer(authUrl),
        }
    })
}

export const getTokenVerificationMetadataPromise = async (
    tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>
): Promise<TokenVerificationMetadataWithPublicKey> => {
    const tokenVerificationMetadata = await tokenVerificationMetadataPromise

    if (!tokenVerificationMetadata) {
        const errorMessage = `Auth library not initialized, rejecting request. 
            This can mean that your API key was invalid or that the request to fetch token metadata failed. 
            Sometimes, this can happen if you are deploying to an environment without external internet access. 
            One workaround is to skip the fetch by passing in manualTokenVerificationMetadata to the initialization function.`
        console.error(errorMessage)
        throw new UnexpectedException(errorMessage)
    }

    try {
        const publicKey = await jose.importSPKI(tokenVerificationMetadata.verifierKey, "RS256")
        return {
            publicKey,
            tokenVerificationMetadata,
        }
    } catch (e) {
        const publicKeyErrorMessage = "Error initializing auth library. Unable to import public key"
        console.error(publicKeyErrorMessage)
        throw new UnexpectedException(publicKeyErrorMessage)
    }
}

function formatIssuer(authUrl: URL): string {
    return authUrl.origin
}
