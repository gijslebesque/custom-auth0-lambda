"use strict";

import { Context, APIGatewayProxyCallback, APIGatewayEvent } from "aws-lambda";
import { authoriser, getPolicyDocument } from "./lib";

module.exports.hello = async (
  event: APIGatewayEvent,
  context: APIGatewayEvent
) => {
  return {
    statusCode: 200,
    body: JSON.stringify(
      {
        message: "Go Serverless v3.0! Your function executed successfully!",
        input: event,
        context,
      },
      null,
      2
    ),
  };
};

module.exports.auth = async (
  event: APIGatewayEvent
  // context: Context,
  // callback: APIGatewayProxyCallback
) => {
  try {
    const user = await authoriser(event);
    return {
      principalId: user.sub,
      //@ts-ignore
      policyDocument: getPolicyDocument("Allow", event.routeArn),
      context: { user },
    };
  } catch (err) {
    throw new Error("Err");
  }
};
