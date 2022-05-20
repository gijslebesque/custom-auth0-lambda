"use strict";
const lib = require("./lib");

module.exports.hello = async (event, context) => {
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

module.exports.auth = async (event, context, callback) => {
  try {
    const data = await lib.auth(event);

    console.log(data);

    return data;
  } catch (err) {
    throw new Error(err);
  }
};
