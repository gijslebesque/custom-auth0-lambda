"use strict";
import { Context, APIGatewayProxyCallback, APIGatewayEvent } from "aws-lambda";

import { authoriser } from "./lib";

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
  event: APIGatewayEvent,
  context: Context,
  callback: APIGatewayProxyCallback
) => {
  try {
    const data = await authoriser(event);

    return data;
  } catch (err) {
    throw new Error("Err");
  }
};
