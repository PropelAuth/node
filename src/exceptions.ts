export class CreateUserException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class MigrateUserException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class CreateOrgException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class AddUserToOrgException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class ChangeUserRoleInOrgException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class RemoveUserFromOrgException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class UpdateOrgException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class ForbiddenException extends Error {
    readonly message: string;
    readonly status: number;
    constructor(message: string) {
        super(message);
        this.message = message;
        this.status = 403;
    }
}

export class MagicLinkCreationException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class AccessTokenCreationException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class UnauthorizedException extends Error {
    readonly message: string;
    readonly status: number;
    constructor(message: string) {
        super(message);
        this.message = message;
        this.status = 401;
    }
}

export class UnexpectedException extends Error {
    readonly message: string;
    readonly status: number;
    constructor(message: string) {
        super(message);
        this.message = message;
        this.status = 503;
    }
}

export class UpdateUserEmailException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class UpdateUserPasswordException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class UpdateUserMetadataException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class UserNotFoundException extends Error {
}

export class EndUserApiKeyValidateException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class EndUserApiKeyDeleteException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class EndUserApiKeyUpdateException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class EndUserApiKeyCreateException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}

export class EndUserApiKeyFetchException extends Error {
    readonly fieldToErrors: {[fieldName: string]: string[]};
    constructor(message: string) {
        super(message);
        this.fieldToErrors = JSON.parse(message);
    }
}
