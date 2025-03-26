<p align="center">
  <a href="https://www.propelauth.com?ref=github" target="_blank" align="center">
    <img src="https://www.propelauth.com/imgs/lockup.svg" width="200">
  </a>
</p>

# PropelAuth Cloudflare Library

A Javascript library for managing authentication, backed by [PropelAuth](https://www.propelauth.com?ref=github).  

[PropelAuth](https://www.propelauth.com?ref=github) makes it easy to add authentication and authorization to your B2B/multi-tenant application.

Your frontend gets a beautiful, safe, and customizable login screen. Your backend gets easy authorization with just a few lines of code. You get an easy-to-use dashboard to config and manage everything.

## Documentation

- Full reference this library is [here](https://docs.propelauth.com/reference/backend-apis/cloudflare-workers)
- Getting started guides for PropelAuth are [here](https://docs.propelauth.com/)

## Installation

```shell
npm install @propelauth/cloudflare-worker
```

## Initialize

`initAuth` performs a one-time initialization of the library.
It will verify your `apiKey` is correct and fetch the metadata needed to verify access tokens in [validateAccessTokenAndGetUserClass](#protect-api-routes).

You can find the `authUrl`, `apiKey`, and `verifierKey` in the **Backend Integration** section in your PropelAuth dashboard.

```typescript
import { initAuth } from '@propelauth/cloudflare-worker'

const {
    validateAccessTokenAndGetUserClass,
    // ...
} = initAuth({
    authUrl: 'REPLACE_ME',
    apiKey: 'REPLACE_ME',
    verifierKey: 'REPLACE_ME',
})
```

## Protect API Routes

After initializing auth, you can verify access tokens by passing it in the Authorization header (formatted `Bearer TOKEN`) to `validateAccessTokenAndGetUserClass`.
You can see more information about the User Class [here](https://docs.propelauth.com/reference/backend-apis/cloudflare-workers#user-class).

```ts
const authorizationHeader = // Get the Authorization header from an HTTP request
try {
    const user = await validateAccessTokenAndGetUserClass(authorizationHeader)
    console.log(`Got request from user ${user.userId}`);
} catch (err) {
    // You can return a 401, or continue the request knowing it wasn't sent from a logged-in user
    console.log(`Unauthorized request ${err}`);
}
```

## Authorization / Organizations

You can also verify which organizations the user is in, and which roles and permissions they have in each organization all through the [User Class](https://docs.propelauth.com/reference/backend-apis/cloudflare-workers#user-class).

### Check Org Membership

Verify that the request was made by a valid user **and** that the user is a member of the specified organization.

```ts
const authorizationHeader = // Get the Authorization header from an HTTP request
const orgId = // get the orgId from somewhere, such as the request URL
try {
    const user = await validateAccessTokenAndGetUserClass(authorizationHeader)
    const org = user.getOrg(orgId)
    if (!org) {
        // return a 403
    }
    console.log(`Got request from user ${user.userId} for org ${org.orgName}`);
} catch (err) {
    // You can return a 401, or continue the request knowing it wasn't sent from a logged-in user
    console.log(`Unauthorized request ${err}`);
}
```

### Check Org Membership and Role

Similar to checking org membership, but will also verify that the user has a specific Role in the organization.

A user has a Role within an organization. By default, the available roles are Owner, Admin, or Member, but these can be configured. These roles are also hierarchical, so Owner > Admin > Member.

```ts
const authorizationHeader = // Get the Authorization header from an HTTP request
const orgId = // get the orgId from somewhere, such as the request URL
try {
    const user = await validateAccessTokenAndGetUserClass(authorizationHeader)
    const org = user.getOrg(orgId)
    if (!org || !org.isRole("Admin")) {
        // return a 403
    }
    console.log(`Got request from Admin user ${user.userId} for org ${org.orgName}`);
} catch (err) {
    // You can return a 401, or continue the request knowing it wasn't sent from a logged-in user
    console.log(`Unauthorized request ${err}`);
}
```

### Check Org Membership and Permission

Similar to checking org membership, but will also verify that the user has the specified permission in the organization.

Permissions are arbitrary strings associated with a role. For example, `can_view_billing`, `ProductA::CanCreate`, and `ReadOnly` are all valid permissions. You can create these permissions in the PropelAuth dashboard.

```ts
const authorizationHeader = // Get the Authorization header from an HTTP request
const orgId = // get the orgId from somewhere, such as the request URL
try {
    const user = await validateAccessTokenAndGetUserClass(authorizationHeader)
    const org = user.getOrg(orgId)
    if (!org || !org.hasPermission("can_view_billing")) {
        // return a 403
    }
    console.log(`User ${user.userId} has 'can_view_billing' permissions for org ${org.orgName}`);
} catch (err) {
    // You can return a 401, or continue the request knowing it wasn't sent from a logged-in user
    console.log(`Unauthorized request ${err}`);
}
```

## Calling Backend APIs

You can also use the library to call the PropelAuth APIs directly, allowing you to fetch users, create orgs, and a lot more.

```ts
const auth = initAuth({
    authUrl: 'REPLACE_ME',
    apiKey: 'REPLACE_ME',
    verifierKey: 'REPLACE_ME',
})

const magicLink = await auth.createMagicLink({
    email: 'user@customer.com',
})
```

See the [API Reference](https://docs.propelauth.com/reference) for more information.


## Questions?

Feel free to reach out at support@propelauth.com

