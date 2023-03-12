const express = require("express")
const app = express()
const mysql = require("mysql")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const cookieParser = require("cookie-parser");
const cors = require('cors')

require("dotenv").config()
const DB_HOST = process.env.DB_HOST
const DB_USER = process.env.DB_USER
const DB_PASSWORD = process.env.DB_PASSWORD
const DB_DATABASE = process.env.DB_DATABASE
const DB_PORT = process.env.DB_PORT
const port = process.env.AUTH_PORT

// refreshTokens save them in database!!!!
let refreshTokens = []

app.use(express.json())
app.use(cookieParser())
app.use(cors())


app.listen(port,
    () => console.log(`Server Started on port ${port}...`))

const db = mysql.createPool({
    connectionLimit: 100,
    host: DB_HOST,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_DATABASE,
    port: DB_PORT
})
db.getConnection((err, connection) => {
    if (err) throw (err)
    console.log("DB connected successful: " + connection.threadId)
})


// accessTokens
function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" })
}

function generateRefreshToken(user) {
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
    refreshTokens.push(refreshToken)
    return refreshToken
}

app.get("/", (req, res) => {
    res.sendStatus(401)
})
app.get("/posts", validateToken, (req, res) => {
    console.log("Token is valid")
    console.log(req.user.user)
    res.send(`${req.user.user} successfully accessed post`)
})

function validateToken(req, res, next) {
    // const token = req.cookies.access_token;
    const authHeader = req.headers["authorization"]
    if (!authHeader) return res.sendStatus(401)

    const token = authHeader && authHeader.split(" ")[1]
    //the request header contains the token "Bearer <token>", split the string and use the second value in the split array.
    if (token == null) res.sendStatus(401)
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {

        if (err) return res.sendStatus(403)

        req.user = user
        next()

    })
}

//CREATE USER
app.post("/createUser", async (req, res) => {
    if (req.body.name.length < 1) res.send("No name")
    const name = req.body.name;
    if (req.body.password.length < 1) res.send("No password")
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const email = req.body.email || 'not set';
    db.getConnection(async (err, connection) => {
        if (err) throw (err)
        const sqlSearch = "SELECT * FROM users WHERE name = ?"
        const search_query = mysql.format(sqlSearch, [name])
        const sqlInsert = "INSERT INTO users VALUES (0,?,?, ?)"
        const insert_query = mysql.format(sqlInsert, [name, hashedPassword, email])
        // ? will be replaced by values
        // ?? will be replaced by string
        await connection.query(search_query, async (err, result) => {
            if (err) throw (err)
            console.log("------> Search Results")
            console.log(result.length)
            if (result.length != 0) {
                connection.release()
                console.log("------> User already exists")
                res.sendStatus(409)
            }
            else {
                await connection.query(insert_query, (err, result) => {
                    connection.release()
                    if (err) throw (err)
                    console.log("--------> Created new User")
                    console.log(result.insertId)
                    res.sendStatus(201)
                })
            }
        }) //end of connection.query()
    }) //end of db.getConnection()
}) //end of app.post()

//LOGIN (AUTHENTICATE USER)



// return res
//     .cookie("access_token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//     })
//     .status(200)
//     .json({ message: "Logged in successfully 😊 👌" });


app.post("/login", (req, res) => {
    const name = req.body.name
    const password = req.body.password
    db.getConnection(async (err, connection) => {
        if (err) throw (err)
        const sqlSearch = "Select * from users where name = ?"
        const search_query = mysql.format(sqlSearch, [name])
        await connection.query(search_query, async (err, result) => {
            connection.release()

            if (err) throw (err)
            if (result.length == 0) {
                console.log("--------> User does not exist")
                res.sendStatus(404)
            }
            else {
                const hashedPassword = result[0].password
                //get the hashedPassword from result
                if (await bcrypt.compare(password, hashedPassword)) {
                    console.log(`---------> Login Successful ${name} is logged in!`)

                    const accessToken = generateAccessToken({ user: req.body.name })
                    const refreshToken = generateRefreshToken({ user: req.body.name })
                    res.cookie("access_token", accessToken, {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === "production",
                    }).status(200).json({ accessToken: accessToken, refreshToken: refreshToken })
                }
                else {
                    console.log("---------> Password Incorrect")
                    res.send("Password incorrect!")
                }
            }
        })
    })
})

app.post("/refreshToken", (req, res) => {
    if (!refreshTokens.includes(req.body.token)) res.status(400).send("Refresh Token Invalid")
    refreshTokens = refreshTokens.filter((c) => c != req.body.token)
    const accessToken = generateAccessToken({ user: req.body.name })
    const refreshToken = generateRefreshToken({ user: req.body.name })
    res.cookie("access_token", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
    }).json({ accessToken: accessToken, refreshToken: refreshToken })
})

app.delete("/logout", (req, res) => {
    refreshTokens = refreshTokens.filter((c) => c != req.body.token)
    res.clearCookie("accessToken").send("Logged out!")
})