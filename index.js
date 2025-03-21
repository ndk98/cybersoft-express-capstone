import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

import rootRoutes from "./src/routes/rootRoutes.js";

const app = express();

// Enable CORS
app.use(
    cors({
        origin: "http://localhost:5173",
        credentials: true,
    })
);

// Parse cookies
app.use(cookieParser());

// Serve static files
app.use(express.static("."));

// Parse JSON bodies (as sent by API clients)
app.use(express.json());

app.use(rootRoutes);

// Default route
app.get("/", (req, res) => {
    return res.send("Hello, this is cybersoft express capstone project!");
});

const port = 3000;

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
