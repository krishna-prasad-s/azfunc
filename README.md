# DAAS authentication

## App registrations

In Azure AD, we created two App registrations.

## [Data as a Service](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Overview/appId/9af01ed2-9768-434f-a175-b6a57e1858b5/isMSAApp/)

    Application (client) ID
    9af01ed2-9768-434f-a175-b6a57e1858b5

    App registration Object ID
    18d398fc-4408-4b39-a7fc-eeea56c78d5c

    Directory (tenant) ID
    1a407a2d-7675-4d17-8692-b3ac285306e4

    Enterprise application Object ID
    e9ed9655-1139-4f8c-9c2b-d5158168bde4

This has [API permissions](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/9af01ed2-9768-434f-a175-b6a57e1858b5/isMSAApp/) `https://graph.microsoft.com/User.Read`.

It has [App roles](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/AppRoles/appId/9af01ed2-9768-434f-a175-b6a57e1858b5/isMSAApp/) which include `Test.read`.

It [exposes an API](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/ProtectAnAPI/appId/9af01ed2-9768-434f-a175-b6a57e1858b5/isMSAApp/) whose application URI is `api://daas`.

## [ITaaP-API-Client](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Overview/appId/2ce95fb2-ebe0-4284-ba32-3e561fe45c36/isMSAApp/)

    Application (client) ID
    2ce95fb2-ebe0-4284-ba32-3e561fe45c36

    App registration Object ID: 3a37e9c7-e404-4b68-938a-738419d16d51

    Directory (tenant) ID
    1a407a2d-7675-4d17-8692-b3ac285306e4

    Enterprise application Object ID: 22b730ec-4d39-4de6-9da6-f659106cd7d7

We created an appRoleAssignment - ITaap-API-Client is assigned the role [Data as a service/Test.read].

## Linking Data as a Service to Function App

## Testing the API

To test the API as ITaaP-as-API, we need an access token.

- we used the client credential flow for server applications. [Msft Docs: Get access without a user](https://docs.microsoft.com/en-us/graph/auth-v2-service)

```
  Grant Type: Client Credentials
  Access Token URL: https://login.microsoftonline.com/1a407a2d-7675-4d17-8692-b3ac285306e4/oauth2/v2.0/token
  Client ID: 2ce95fb2-ebe0-4284-ba32-3e561fe45c36
  Client secret: {{api_clientsecret}}
  Scope: api://daas/.default
```

POST HTTP request for the above (replace {{api_clientsecret}})

```
POST https://login.microsoftonline.com/1a407a2d-7675-4d17-8692-b3ac285306e4/oauth2/v2.0/token HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded

client_id=2ce95fb2-ebe0-4284-ba32-3e561fe45c36
&scope=api%3A%2F%2Fdaas%2F.default
&client_secret={{api_clientsecret}}
&grant_type=client_credentials
```

Curl command for the above (replace {{api_clientsecret}})

```sh
curl -X POST https://login.microsoftonline.com/1a407a2d-7675-4d17-8692-b3ac285306e4/oauth2/v2.0/token -H "Content-Type: application/x-www-form-urlencoded" -d "client_id=2ce95fb2-ebe0-4284-ba32-3e561fe45c36
&scope=api%3A%2F%2Fdaas%2F.default
&client_secret={{api_clientsecret}}
&grant_type=client_credentials"
```

https://docs.microsoft.com/en-us/graph/auth-v2-user
