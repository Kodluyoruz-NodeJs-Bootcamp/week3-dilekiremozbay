Gusto & RemoteTeam Bootcamp3 3rd HOMEWORK

Description
Authentication with JWT Token and Sessions in Typescript.Mongoose,MongoDB,Express were used.

Usage
$ npm install

$ npm run startdev(development)
$ npm run startprod(producement)

Environment Variables:
{
"dev": {
"PORT": "2000",
"DB_USER": "api",
"DB_PASS": "api",
"DB_HOST": "localhost",
"DB_PORT": "27017",
"DB_PROTOCOL": "mongodb",
"DB_NAME":
"DB_PARAMS":
"SECRET_ACCESS_TOKEN": "123456789",
"ACCESS_TOKEN_EXPIRY": "15m",
"SECRET_REFRESH_TOKEN": "91234534",
"REFRESH_TOKEN_EXPIRY": "15m"
},
"prod": {
"PORT": "2001",
"DB_USER":
"DB_PASS":
"DB_HOST":
"DB_PORT": "27017",
"DB_PROTOCOL": "mongodb+srv",
"DB_NAME":
"DB_PARAMS":
"SECRET_ACCESS_TOKEN": "abcdef",
"ACCESS_TOKEN_EXPIRY": "15m",
"SECRET_REFRESH_TOKEN": "sdfgfg",
"REFRESH_TOKEN_EXPIRY": "15d"
}
}

License
MIT License.
