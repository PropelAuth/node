import { TokenVerificationMetadata, UnexpectedException } from "@propelauth/node-apis"
import * as jose from "jose"

export interface TokenVerificationMetadataWithPublicKey {
    tokenVerificationMetadata: TokenVerificationMetadata
    publicKey: jose.KeyLike
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
