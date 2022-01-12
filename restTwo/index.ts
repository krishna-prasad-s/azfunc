import { AzureFunction, Context, HttpRequest } from "@azure/functions"
import * as intercept from 'azure-function-log-intercept'

import * as jwt from 'jsonwebtoken';
import * as jwksClient from 'jwks-rsa';
const DISCOVERY_KEYS_ENDPOINT = "https://login.microsoftonline.com/common/discovery/keys";


const validateJwt = async (req: HttpRequest): Promise<null | jwt.JwtPayload> => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];

        // Decode the token
        const decoded = jwt.decode(token, { complete: true });
        console.log(`Decoded header: ${JSON.stringify(decoded.header)}`)
        const client = jwksClient({
            jwksUri: DISCOVERY_KEYS_ENDPOINT
        });
        const key = await client.getSigningKey(decoded.header.kid);
        const signingKey = key.getPublicKey();
        const validationOptions = {
            audience: "api://daas",
            "iss": "https://sts.windows.net/1a407a2d-7675-4d17-8692-b3ac285306e4/",
        }
        // const verifiedToken = { 
        //     "aud": "api://daas", 
        //     "iss": "https://sts.windows.net/1a407a2d-7675-4d17-8692-b3ac285306e4/", 
        //     "iat": 1641973345, 
        //     "nbf": 1641973345, 
        //     "exp": 1641977245, 
        //     "aio": "E2ZgYHjp/+BUtt60hJgPy+7lfPtsBgA=", 
        //     "appid": "2ce95fb2-ebe0-4284-ba32-3e561fe45c36",  // Application Id for ITaaP-API-Client
        //     "appidacr": "1", 
        //     "idp": "https://sts.windows.net/1a407a2d-7675-4d17-8692-b3ac285306e4/", 
        //     "oid": "22b730ec-4d39-4de6-9da6-f659106cd7d7", // Object ID for ITaaP-API-Client in Enterprise Applications
        //     "rh": "0.AQkALXpAGnV2F02GkrOsKFMG5LJf6Szg64RCujI-Vh_kXDYJAAA.", 
        //     "roles": ["test.read"], 
        //     "sub": "22b730ec-4d39-4de6-9da6-f659106cd7d7", 
        //     "tid": "1a407a2d-7675-4d17-8692-b3ac285306e4", // Tenant ID
        //     "uti": "C5AdlXwQWUSqTOKmBVyfAQ", 
        //     "ver": "1.0" };

        try {
            console.log(`Signing key: ${JSON.stringify({ signingKey })}`);
            const verifiedToken: jwt.JwtPayload = jwt.verify(token, signingKey, validationOptions) as jwt.JwtPayload;
            console.log(`Verified token: ${JSON.stringify({ verifiedToken })}`);
            return verifiedToken;
        } catch (err) {
            console.log('Token is not verified.')
            console.log(err);
            return null;
        }
    } else {
        console.log('No auth token.')
        //console.res.sendStatus(401);
        return null;
    }
};

const isAuthorized = async (rolename, req) => {
    const verifiedToken = await validateJwt(req);
    if (verifiedToken && verifiedToken.roles.includes(rolename)) {
        console.log(`Authorized: Verified token has role ${rolename}`);
        return true;
    } else {
        console.log(`Not authorized: Token does not have role ${rolename}`);
        return false;
    }

}


const httpTrigger: AzureFunction = async function (context: Context, req: HttpRequest): Promise<void> {
    intercept(console); // Redirect console to context.
    context.log('RestTwo processing. Check authorization.');
    const authorized = await isAuthorized(req, 'test.read');
    if (authorized) {
        const name = (req.query.name || (req.body && req.body.name));
        const responseMessage = name
            ? "Hello, " + name + "."
            : "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.";
        context.res = {
            status: 200,
            body: responseMessage
        }
    } else {
        context.res = {
            status: 403,
            body: 'Not authorized'
        }
    }
    context.log('Finished');

};

export default httpTrigger;