import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { PrismaClient } from "@prisma/client";

dotenv.config();

const prisma = new PrismaClient();

const createAccessToken = (payload) => {
    return jwt.sign({ payload }, process.env.ACCESS_TOKEN_SECRET, {
        algorithm: "HS256",
        expiresIn: "1d",
    });
};

const createRefreshToken = (payload) => {
    return jwt.sign({ payload }, process.env.ACCESS_TOKEN_SECRET, {
        algorithm: "HS256",
        expiresIn: "7d",
    });
};

const verifyAccessToken = (token) => {
    try {
        return jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    } catch (e) {
        return null;
    }
};

const middleware = async (req, res, next) => {
    const { authorization } = req.headers;

    if (!authorization) {
        return res.status(401).json({ message: "Access token not found" });
    }

    const checkToken = verifyAccessToken(authorization);

    if (!checkToken) {
        return res.status(403).json({ message: "Invalid access token" });
    }

    const userId = checkToken.payload.user_id;

    const user = await prisma.users.findFirst({
        where: {
            user_id: parseInt(userId),
        },
    });

    if (!user) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    req.headers.user_id = userId;

    next();
};

export { createAccessToken, createRefreshToken, verifyAccessToken, middleware };
