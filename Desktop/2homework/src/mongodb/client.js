const dotenv = require("dotenv");
dotenv.config();
const { MongoClient } = require("mongodb");
const { apiDescriptor } = require("prettier");

const client = new MongoClient(
  (CONNECTIONSTRING = "mongodb://localhost:27017/homework2")
);

exports.client = client;
console.log("connection string");

//"mongodb://Admin333:333333@cluster0.hmv3y.mongodb.net/homework2?retryWrites=true&w=majority"
//("mongodb://api:api@localhost/homework2?authSource=admin");
