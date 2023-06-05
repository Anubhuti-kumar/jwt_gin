# jwt_gin
This project is all about of implementation of JWT (token and refresh Token) using golang with gin package and mongoDB


To ru this project follow these steps:

1. go mod init jwt_gin
2. go mod tidy
3. go run .

endpoints :
POST : signup --> localhost:9900/user/signup
POST : login --> localhost:9900/user/login
GET : getUsers --> localhost:9900/users (can only accessed by users of type "ADMIN", as it show details related to all users)
GET : getUser --> localhost:9900/users/:id (show the details of only a user)
