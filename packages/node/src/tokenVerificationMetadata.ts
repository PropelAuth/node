import { TokenVerificationMetadata, UnexpectedException } from "@propelauth/node-apis"
import * as jose from "jose"

export interface TokenVerifier {
    verify(bearerToken: string): Promise<jose.JWTPayload>
}

const JWKS_PATH = "/.well-known/jwks.json"
const ALGORITHMS = ["RS256"]

/**
 * Verifies tokens against the keys published at `{authUrl}/.well-known/jwks.json`.
 * The JWKS is fetched once up front and cached. jose re-fetches it when a token
 * carries a `kid` that isn't in the cache.
 */
export async function createJwksTokenVerifier(authUrl: URL): Promise<TokenVerifier> {
    const jwks = jose.createRemoteJWKSet(new URL(JWKS_PATH, authUrl.origin))
    const options: jose.JWTVerifyOptions = { algorithms: ALGORITHMS, issuer: authUrl.origin }

    // Fetch eagerly so the first request doesn't pay for it. If this fails, jose
    // fetches on first use instead.
    await jwks.reload().catch((err: unknown) => {
        console.error("Error fetching JWKS, will retry on the first request. ", err)
    })

    return {
        verify: async (bearerToken) => {
            const { payload } = await jose.jwtVerify(bearerToken, jwks, options)
            return payload
        },
    }
}

/**
 * Verifies tokens against manually supplied PEM public keys: `verifierKey` first,
 * then `fallbackVerifierKey` if present.
 */
export async function createManualTokenVerifier(
    tokenVerificationMetadata: TokenVerificationMetadata
): Promise<TokenVerifier> {
    const pems = [tokenVerificationMetadata.verifierKey, tokenVerificationMetadata.fallbackVerifierKey].filter(
        (pem): pem is string => typeof pem === "string" && pem.length > 0
    )

    let publicKeys: jose.KeyLike[]
    try {
        publicKeys = await Promise.all(pems.map((pem) => jose.importSPKI(pem, "RS256")))
    } catch (e) {
        const publicKeyErrorMessage = "Error initializing auth library. Unable to import public key"
        console.error(publicKeyErrorMessage)
        throw new UnexpectedException(publicKeyErrorMessage)
    }

    const options: jose.JWTVerifyOptions = { algorithms: ALGORITHMS, issuer: tokenVerificationMetadata.issuer }

    return {
        verify: async (bearerToken) => {
            let lastError: unknown
            for (const publicKey of publicKeys) {
                try {
                    const { payload } = await jose.jwtVerify(bearerToken, publicKey, options)
                    return payload
                } catch (e: unknown) {
                    // Only a signature mismatch means "try the next key". The signature is
                    // checked before the claims, so an expiry/issuer error means this key
                    // was the signer and the error should surface as-is.
                    if ((e as jose.errors.JOSEError)?.code !== "ERR_JWS_SIGNATURE_VERIFICATION_FAILED") {
                        throw e
                    }
                    lastError = e
                }
            }
            throw lastError
        },
    }
}
