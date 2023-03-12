const express = require("express")
const app = express()
const mysql = require("mysql")
const jwt = require("jsonwebtoken")
const cookieParser = require("cookie-parser");
const cors = require('cors')

require("dotenv").config()
const DB_HOST = process.env.DB_HOST
const DB_USER = process.env.DB_USER
const DB_PASSWORD = process.env.DB_PASSWORD
const DB_DATABASE = process.env.DB_DATABASE
const DB_PORT = process.env.DB_PORT
const port = process.env.PORT

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

app.get("/", async (req, res) => {
    db.getConnection(async (err, connection) => {
        await connection.query("SELECT * FROM users", async (err, result) => {
            if (err) throw (err)
            connection.release()
            console.log("------> Search Results")
            console.log(result)
            let data = result.map(i => ({ name: i.name, email: i.email }))
            res.send(data)
        })
    })
})

app.get("/posts", validateToken, (req, res) => {
    res.send(`${req.user.user} successfully accessed posts`)
})

function validateToken(req, res, next) {
    const token = req.cookies?.accessToken
    if (!token) return res.sendStatus(401)

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        req.user = user
        next()
    })
} 