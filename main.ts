import express from "express"
import cookieParser from "cookie-parser"
const app = express()
app.use(express.json())
app.use(express.static("."))
app.use(cookieParser())
app.listen(8080)

// import rootRoutes
import rootRoute from "./src/routes/rootRoute"
app.use("/api", rootRoute)