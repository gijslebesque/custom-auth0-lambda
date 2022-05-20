// extract and return the Bearer Token from the Lambda event parameters

const util = require("util");
const jwksClient = require("jwks-rsa");
const jwt = require("jsonwebtoken");

const AUTH0_CLIENT_AUDIENCE = process.env.AUTH0_CLIENT_AUDIENCE;
const AUTH0_CLIENT_ISSUER = process.env.AUTH0_CLIENT_ISSUER;
const AUTH0_JWKS_URI = process.env.AUTH0_JWKS_URI;

const getToken = (headers) => {
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
  jwksUri: AUTH0_JWKS_URI,
});

const getPolicyDocument = (effect, resource) => {
  const policyDocument = {
    Version: "2012-10-17", // default version
    Statement: [
      {
        Action: "execute-api:Invoke", // default action
        Effect: effect,
        Resource: resource,
      },
    ],
  };

  return policyDocument;
};

module.exports.auth = async (event) => {
  const token = getToken(event.headers);

  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || !decoded.header || !decoded.header.kid) {
    throw new Error("invalid token");
  }

  const getSigningKey = util.promisify(client.getSigningKey);
  return getSigningKey(decoded.header.kid)
    .then((key) => {
      const signingKey = key.publicKey || key.rsaPublicKey;
      return jwt.verify(token, signingKey, jwtOptions);
    })
    .then((decoded) => ({
      principalId: decoded.sub,
      policyDocument: getPolicyDocument("Allow", event.routeArn),
      context: { scope: decoded.scope },
    }));
};
