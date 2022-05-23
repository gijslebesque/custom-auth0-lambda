import jwksClient from "jwks-rsa";
import jwt from "jsonwebtoken";
import {
  APIGatewayEvent,
  APIGatewayProxyEventHeaders,
  PolicyDocument,
} from "aws-lambda";

const { AUTH0_CLIENT_AUDIENCE, AUTH0_CLIENT_ISSUER, AUTH0_JWKS_URI } =
  process.env;

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

export const getPolicyDocument = (
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

interface IKey {
  publicKey?: string;
  rsaPublicKey?: string;
}

export const authoriser = async (event: APIGatewayEvent) => {
  const token = getToken(event.headers); //jwt

  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || !decoded.header || !decoded.header.kid) {
    throw new Error("invalid token");
  }

  const key: IKey = await client.getSigningKey(decoded.header.kid);

  const signingKey = key?.publicKey || key?.rsaPublicKey;

  if (!signingKey) {
    throw new Error("invalid token");
  }

  return jwt.verify(token, signingKey, jwtOptions);
};
