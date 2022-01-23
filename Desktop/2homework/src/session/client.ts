import "dotenv/config";
import { MongoClient } from "mongodb";

const mongoURL = buildMongoURL(process.env);

export const client = new MongoClient(mongoURL);

function buildMongoURL(env: NodeJS.ProcessEnv) {
  const creds = buildUserCredentials(env);
  const dbProtocol = env.DB_PROTOCOL || "mongodb";
  const srvFeatureEnabled = dbProtocol === "mongodb+srv";
  const dbPort = srvFeatureEnabled ? "" : `:${env.DB_PORT}`;
  const dbAddr = `${env.DB_HOST}${dbPort}`;
  const dbName = env.DB_NAME;
  const dbParams = buildDBParamsString(env);

  return `${dbProtocol}://${creds}${dbAddr}/${dbName}${dbParams}`;
}

function buildUserCredentials(env: NodeJS.ProcessEnv) {
  const user = env.DB_USER;
  const pass = env.DB_PASS;

  if (user && pass) {
    return `${user}:${pass}@`;
  } else if (user) {
    return `${user}@`;
  } else if (pass) {
    throw new Error("Password provided without username");
  }

  return "";
}

function buildDBParamsString(env: NodeJS.ProcessEnv) {
  const params = env.DB_PARAMS;

  if (params) {
    return `?${params}`;
  }

  return "";
}
