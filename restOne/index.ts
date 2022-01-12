import { AzureFunction, Context, HttpRequest } from "@azure/functions"


import jwt = require('jsonwebtoken');
import jwksClient = require('jwks-rsa');
const DISCOVERY_KEYS_ENDPOINT = "https://login.microsoftonline.com/common/discovery/keys";


// const validateJwt = async (req, context) => {
//     const authHeader = req.headers.authorization;
//     if (authHeader) {
//         const token = authHeader.split(' ')[1];

//         const validationOptions = {
//             audience: "api://daas",
//             roles: ["test.read"]
//         }

//         try {
//                 jwt.verify(token, getSigningKeys, validationOptions);
//                 return true;
//         } catch (err) {
//             context.log(err);
//             return false;
//         }
//     } else {
//         return false;
//     }
// };

const getSigningKeys = (header, callback) => {
    var client = jwksClient({
        jwksUri: DISCOVERY_KEYS_ENDPOINT
    });

    client.getSigningKey(header.kid, function (err, key) {

        var signingKey = (key as jwksClient.CertSigningKey).publicKey || (key as jwksClient.RsaSigningKey).rsaPublicKey;
        callback(null, signingKey);
    });
}

const validateJwt = (req, res) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        const validationOptions = {
            audience: "api://daas",
            roles: ["test.error"]
        }

        jwt.verify(token, getSigningKeys, validationOptions, (err, payload) => {
            if (err) {
                console.log("some error from jwt verify");
                console.log(err);
                return false;//res.sendStatus(403);
            }
            console.log("Roles :"+payload.roles);
            payload.roles.forEach(role => {
                if (role == "test.read") {
                    console.log("role matched")
                    return true;
                }
            });
            return false;//res.status(200);
        });
    } else {
        console.log("no auth header");
        return false;//res.sendStatus(401);
    }
};



const httpTrigger: AzureFunction = async function (context: Context, req: HttpRequest): Promise<void> {
    context.log('HTTP trigger function processed a request.');
    const x =  await validateJwt(req, context);
    context.log("validation respose is :" + x);
    const name = (req.query.name || (req.body && req.body.name));
    const responseMessage = name
        ? "Hello, " + name + ". validation response was:"+ x +". This HTTP triggered function executed successfully. changed by kp"
        : "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.";

    // context.log(JSON.stringify(context, null, 2));
    // context.log(JSON.stringify(req.headers, null, 2));

    context.res = {
        // status: 200, /* Defaults to 200 */
        body: responseMessage
    };

};

export default httpTrigger;