export default class UpdateUserMetadataException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}
