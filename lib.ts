import jwksClient from "jwks-rsa";
import jwt from "jsonwebtoken";
import {
  APIGatewayEvent,
  APIGatewayProxyEventHeaders,
  PolicyDocument,
} from "aws-lambda";

const AUTH0_CLIENT_AUDIENCE = process.env.AUTH0_CLIENT_AUDIENCE;
const AUTH0_CLIENT_ISSUER = process.env.AUTH0_CLIENT_ISSUER;
const AUTH0_JWKS_URI = process.env.AUTH0_JWKS_URI;

const getToken = (headers: APIGatewayProxyEventHeaders) => {
  const authorizationBearer = headers?.authorization;
  if (!authorizationBearer) {
    throw new Error('Expected "headers.authorization" parameter to have value');
  }

  const match = authorizationBearer.match(/^Bearer (.*)$/);
  if (!match || match.length < 2) {
    throw new Error(
      `Invalid Authorization token - ${authorizationBearer} does not match "Bearer .*"`
    );
  }
  return match[1];
};

const jwtOptions = {
  audience: AUTH0_CLIENT_AUDIENCE,
  issuer: AUTH0_CLIENT_ISSUER,
};

const client = jwksClient({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 10, // Default value
  jwksUri: AUTH0_JWKS_URI ?? "",
});

const getPolicyDocument = (
  effect: "Allow",
  resource: string
): PolicyDocument => {
  return {
    Version: "2012-10-17", // default version
    Statement: [
      {
        Action: "execute-api:Invoke", // default action
        Effect: effect,
        Resource: resource,
      },
    ],
  };
};

//@TODO find out why types are not working

export const authoriser = async (event: APIGatewayEvent) => {
  const token = getToken(event.headers);

  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || !decoded.header || !decoded.header.kid) {
    throw new Error("invalid token");
  }

  const key = await client.getSigningKey(decoded.header.kid);

  //@ts-ignore
  const signingKey = key.publicKey || key?.rsaPublicKey;

  const user = await jwt.verify(token, signingKey, jwtOptions);

  return {
    principalId: user.sub,
    //@ts-ignore
    policyDocument: getPolicyDocument("Allow", event.routeArn),
    context: { user },
  };
};
