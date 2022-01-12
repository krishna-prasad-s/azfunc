import { AzureFunction, Context, HttpRequest } from "@azure/functions"
import * as intercept from 'azure-function-log-intercept'

import * as jwt from 'jsonwebtoken';
import * as jwksClient from 'jwks-rsa';
const DISCOVERY_KEYS_ENDPOINT = "https://login.microsoftonline.com/common/discovery/keys";


const validateJwt = async (req: HttpRequest, context: Context) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];

        // Decode the token
        const decoded = jwt.decode(token, { complete: true });
        context.log(decoded.header);
        context.log(decoded.payload)
        const client = jwksClient({
            jwksUri: DISCOVERY_KEYS_ENDPOINT
        });
        const key = await client.getSigningKey(decoded.header.kid);
        const signingKey = key.getPublicKey();
        const validationOptions = {
            audience: "api://daas",
            roles: ["test.error"]
        }

        try {
            context.log('Signing key');
            context.log(JSON.stringify({ signingKey }));
            const payload = jwt.verify(token, signingKey, validationOptions);
            context.log('Payload of verified token');
            context.log(JSON.stringify({ payload }));
            //context.res.sendStatus(200);
            return true;
        } catch (err) {
            context.log('Token is not verified.')
            context.log(err);
            //context.res.sendStatus(403);
            return false;
        }
    } else {
        context.log('No auth token.')
        //context.res.sendStatus(401);
        return false;
    }
};



const httpTrigger: AzureFunction = async function (context: Context, req: HttpRequest): Promise<void> {
    intercept(console);
    context.log('HTTP trigger function processed a request.');
    const x = await validateJwt(req, context);
    context.log("validation respose is :" + x);
    if (x) {
        const name = (req.query.name || (req.body && req.body.name));
        const responseMessage = name
            ? "Hello, " + name + ". validation response was:" + x + ". This HTTP triggered function executed successfully. changed by kp"
            : "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.";

        // context.log(JSON.stringify(context, null, 2));
        // context.log(JSON.stringify(req.headers, null, 2));

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